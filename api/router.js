// Vercel Function: every /api/* request is rewritten here (see vercel.json).
// Text data lives in Upstash Redis; files and photos live in a private Vercel Blob store.
import { put, get, del } from '@vercel/blob';
import { onRequest, SetupError } from '../lib/core.js';

const REDIS_URL = () => process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = () => process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const isBinary = (k) => k.startsWith('photo/') || k.startsWith('doc-file/');
const blobPath = (k) => k.replace('doc-file/', 'doc/');

async function redis(cmd) {
  const r = await fetch(REDIS_URL(), { method: 'POST', headers: { Authorization: 'Bearer ' + REDIS_TOKEN(), 'Content-Type': 'application/json' }, body: JSON.stringify(cmd) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error('redis ' + r.status + ' ' + (j.error || ''));
  return j.result;
}
function blobApi() {
  if (globalThis.__TEST_BLOB__) return globalThis.__TEST_BLOB__;
  if (!process.env.BLOB_READ_WRITE_TOKEN) throw new SetupError('BLOB_READ_WRITE_TOKEN (connect a Blob store)');
  return { put, get, del };
}

// The core expects a small key–value store; this adapter maps it onto Redis + Blob.
const DB = {
  async get(key, opts) {
    const type = typeof opts === 'string' ? opts : opts?.type;
    if (isBinary(key)) { const r = await this.getWithMetadata(key, { type: 'arrayBuffer' }); return r.value; }
    const v = await redis(['GET', key]);
    if (v == null) return null;
    return type === 'json' ? JSON.parse(v) : v;
  },
  async getWithMetadata(key) {
    const b = blobApi();
    let r = null;
    try { r = await b.get(blobPath(key), { access: 'private' }); } catch (e) { if (!/not.?found/i.test(String(e && (e.name || e.message)))) throw e; }
    if (!r || !r.stream) return { value: null, metadata: null };
    return { value: await new Response(r.stream).arrayBuffer(), metadata: { type: r.blob && r.blob.contentType } };
  },
  async put(key, value, opts = {}) {
    if (isBinary(key)) {
      await blobApi().put(blobPath(key), value, { access: 'private', allowOverwrite: true, addRandomSuffix: false,
        contentType: opts.metadata?.type || 'application/octet-stream' });
      return;
    }
    const cmd = ['SET', key, typeof value === 'string' ? value : JSON.stringify(value)];
    if (opts.expirationTtl) cmd.push('EX', String(opts.expirationTtl));
    await redis(cmd);
  },
  async delete(key) {
    if (isBinary(key)) { try { await blobApi().del(blobPath(key)); } catch (e) { /* already gone */ } return; }
    await redis(['DEL', key]);
  },
};

async function handle(request) {
  const env = {
    ...process.env,
    DB: REDIS_URL() && REDIS_TOKEN() ? DB : undefined,
    DB_MISSING: 'Upstash Redis (KV_REST_API_URL / KV_REST_API_TOKEN) — add it from Vercel Storage',
  };
  return onRequest({ request, env });
}
export const GET = handle;
export const POST = handle;
export const DELETE = handle;
