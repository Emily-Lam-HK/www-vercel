// emilylam.hk backend core (shared logic). On Vercel it is called from api/router.js.
// Handles everything under /api/*: links, documents, Log posts with photos, status,
// document unlock (email code + password), requests and the admin page.

const SECTIONS = ['main', 'portfolio', 'certs', 'books', 'projects'];
const DEFAULT_DOCS = [
  { id: 'cv', name: 'CV', section: 'main' },
  { id: 'resume', name: 'Résumé', section: 'main' },
  { id: 'portfolio-personal', name: 'Personal', section: 'portfolio' },
  { id: 'portfolio-occupational', name: 'Occupational', section: 'portfolio' },
  { id: 'portfolio-ap2d', name: 'AP 2D Art & Design', extra: '5/5', section: 'portfolio' },
  { id: 'portfolio-apdrawing', name: 'AP Drawing', extra: '5/5', section: 'portfolio' },
  { id: 'cert-soty', name: 'Student of the Year — Scientist & Mathematician', section: 'certs' },
  { id: 'cert-speech', name: 'Champion, Hong Kong Schools Speech Festival', section: 'certs' },
  { id: 'cert-mediation', name: 'Champion, Peer Mediation Competition', section: 'certs' },
  { id: 'cert-biology', name: 'Gold Award, Biology Challenge', section: 'certs' },
  { id: 'cert-stem', name: 'Finalist, STEM Challenge', section: 'certs' },
  { id: 'cert-hkfyg', name: 'Finalist, HKFYG English Public Speaking Contest', section: 'certs' },
  { id: 'book-dnawayhome', name: 'DNA Way Home', section: 'books' },
  { id: 'book-dnaindigestion', name: 'DNA in Digestion', section: 'books' },
  { id: 'project-alginate', name: 'Alginate', section: 'projects' },
  { id: 'project-drdd', name: 'Date Rape Drug Detector', section: 'projects' },
  { id: 'project-medaitor', name: 'MedAitor', section: 'projects' },
];
const DEFAULT_LINKS = [
  { id: 'linkedin', label: 'LinkedIn', url: 'https://www.linkedin.com/in/emilylam-hk', note: '', color: '#0A66C2', icon: 'briefcase' },
  { id: 'instagram', label: 'Instagram', url: 'https://www.instagram.com/emilylam.hk', note: '', color: '#C13584', icon: 'camera' },
  { id: 'bufferbox', label: 'bufferbox.ing', url: 'https://bufferbox.ing', note: 'my current project', color: '#1F5F8B', icon: 'box' },
  { id: 'i2ol', label: 'i2ol.org', url: 'https://i2ol.org', note: 'the NGO I’m working at', color: '#6B3FA0', icon: 'globe' },
];
const ICONS = ['briefcase', 'camera', 'box', 'globe', 'link', 'flask', 'book', 'star', 'play', 'mail', 'notebook'];
const STATUSES = ['free', 'busy', 'travel', 'heads'];
const MAX_FILE = 4 * 1024 * 1024;
const MAX_PHOTO = 3 * 1024 * 1024;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOC_ID_RE = /^[a-z0-9-]{1,60}$/;
const KEY_RE = /^[A-Za-z0-9_-]{6,40}$/;
const enc = new TextEncoder();

export class SetupError extends Error {}
class HttpError extends Error { constructor(code, status) { super(code); this.code = code; this.status = status; } }

/* ---------- small helpers ---------- */
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});
const fail = (error, status = 400) => json({ error }, status);
const clean = (s, n) => String(s ?? '').trim().slice(0, n);
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlText = (str) => b64url(enc.encode(str));
const fromB64urlText = (s) => { const b = atob(s.replace(/-/g, '+').replace(/_/g, '/')); return new TextDecoder().decode(Uint8Array.from(b, (c) => c.charCodeAt(0))); };
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
const randId = (n = 9) => b64url(crypto.getRandomValues(new Uint8Array(n)));
async function sha(s) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function makeApi(env) {
  const KV = env.DB;
  if (!KV) throw new SetupError(env.DB_MISSING || 'DB storage');
  const secret = () => { const s = env.SESSION_SECRET; if (!s || s.length < 16) throw new SetupError('SESSION_SECRET'); return s; };
  let hmacKey;
  async function hmac(data) {
    hmacKey ||= await crypto.subtle.importKey('raw', enc.encode(secret()), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return b64url(await crypto.subtle.sign('HMAC', hmacKey, enc.encode(data)));
  }
  async function sign(payload, ttl) {
    const body = b64urlText(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttl }));
    return body + '.' + await hmac(body);
  }
  async function verify(token, roles) {
    if (!token || typeof token !== 'string' || !token.includes('.')) return null;
    const [body, sig] = token.split('.');
    if (!safeEqual(sig, await hmac(body))) return null;
    let p; try { p = JSON.parse(fromB64urlText(body)); } catch (e) { return null; }
    if (!p.exp || p.exp < Date.now() / 1000) return null;
    if (roles && !roles.includes(p.role)) return null;
    return p;
  }
  async function hashPw(pw) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 10000, hash: 'SHA-256' }, key, 256);
    return hex(salt) + ':' + hex(bits);
  }
  async function checkPw(pw, stored) {
    if (!stored || !stored.includes(':')) return false;
    const [saltHex, h] = stored.split(':');
    const salt = Uint8Array.from(saltHex.match(/../g), (x) => parseInt(x, 16));
    const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 10000, hash: 'SHA-256' }, key, 256);
    return safeEqual(hex(bits), h);
  }
  const getJSON = async (k, d) => (await KV.get(k, { type: 'json' })) ?? d;
  const setJSON = (k, v, opts) => KV.put(k, JSON.stringify(v), opts);
  async function limited(key, max, windowSec) {
    const k = 'rl/' + await sha(key); const now = Date.now();
    const r = await getJSON(k, null);
    const next = !r || now - r.start > windowSec * 1000 ? { start: now, count: 1 } : { start: r.start, count: r.count + 1 };
    await setJSON(k, next, { expirationTtl: Math.max(60, windowSec) });
    return next.count > max;
  }
  async function sendMail(to, subject, text) {
    if (!env.RESEND_API_KEY || !env.MAIL_FROM) throw new SetupError('RESEND_API_KEY / MAIL_FROM');
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, text }),
    });
    if (!r.ok) throw new Error('send_failed ' + r.status + ' ' + (await r.text()).slice(0, 200));
  }
  return { KV, secret, sign, verify, hashPw, checkPw, getJSON, setJSON, limited, sendMail,
    getDocs: () => getJSON('docs', DEFAULT_DOCS), getLinks: () => getJSON('links', DEFAULT_LINKS),
    site: () => (env.SITE_URL || 'https://emilylam.hk').replace(/\/$/, '') };
}

/* Remove hidden metadata from images: JPEG APP1–APP15 (EXIF, GPS, XMP, IPTC) and comments; PNG text/EXIF/time chunks. */
export function stripImage(buf) {
  const b = new Uint8Array(buf); const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const cat = (parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
  if (b[0] === 0xFF && b[1] === 0xD8) {
    const parts = [b.subarray(0, 2)]; let i = 2;
    while (i + 4 <= b.length) {
      if (b[i] !== 0xFF) return null;
      const marker = b[i + 1];
      if (marker === 0xDA) { parts.push(b.subarray(i)); break; }
      const len = dv.getUint16(i + 2);
      if (!((marker >= 0xE1 && marker <= 0xEF) || marker === 0xFE)) parts.push(b.subarray(i, i + 2 + len));
      i += 2 + len;
    }
    return { data: cat(parts), type: 'image/jpeg' };
  }
  const sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  if (sig.every((v, j) => b[j] === v)) {
    const parts = [b.subarray(0, 8)]; let i = 8;
    const drop = new Set(['tEXt', 'iTXt', 'zTXt', 'eXIf', 'tIME']);
    while (i + 12 <= b.length) {
      const len = dv.getUint32(i); const type = String.fromCharCode(...b.subarray(i + 4, i + 8)); const end = i + 12 + len;
      if (!drop.has(type)) parts.push(b.subarray(i, end));
      i = end; if (type === 'IEND') break;
    }
    return { data: cat(parts), type: 'image/png' };
  }
  return null;
}

async function readJSON(request) {
  const text = await request.text();
  if (text.length > 1024 * 1024) throw new HttpError('too_big', 413);
  try { return text ? JSON.parse(text) : {}; } catch (e) { return {}; }
}
async function readBinary(request, max) {
  const buf = await request.arrayBuffer();
  if (buf.byteLength > max) throw new HttpError('too_big', 413);
  return buf;
}

/* Who opened what: kept so Emily can see which verified email unlocked or opened each document. */
async function logAccess(A, e) {
  try {
    const log = await A.getJSON('access-log', []);
    log.unshift({ at: new Date().toISOString(), ...e });
    await A.setJSON('access-log', log.slice(0, 2000));
  } catch (err) { console.error('access log', err); }
}

/* Admin sign-ins: every attempt on the admin page, successful or not. */
async function logAdmin(A, e) {
  try {
    const log = await A.getJSON('admin-log', []);
    log.unshift({ at: new Date().toISOString(), ...e });
    await A.setJSON('admin-log', log.slice(0, 300));
  } catch (err) { console.error('admin log', err); }
}

/* Email Emily whenever someone unlocks her documents. */
async function alertUnlock(A, env, email, how, w) {
  if (!env.OWNER_EMAIL || !env.RESEND_API_KEY || !env.MAIL_FROM) return;
  try {
    await A.sendMail(env.OWNER_EMAIL, `${email} unlocked your documents`,
      `${email} just unlocked your documents on emilylam.hk using ${how}.\n\nWhen: ${new Date().toUTCString()}\nWhere: ${[w.city, w.country].filter(Boolean).join(', ') || 'unknown'}\n\nSee what they open: ${A.site()}/admin.html`);
  } catch (err) { console.error('unlock alert', err); }
}

/* ---------- handler ---------- */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const route = (url.searchParams.get('path') ?? url.pathname.replace(/^\/api\/?/, '')).replace(/\/$/, '');
  const m = request.method;
  const ip = request.headers.get('CF-Connecting-IP') || (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
  const bearer = () => (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('t') || '';
  const allowed = (p, doc) => p.all === true || (p.docs || []).includes(doc.id) || (p.sections || []).includes(doc.section);
  const who = () => {
    let city = request.headers.get('x-vercel-ip-city') || '';
    try { city = decodeURIComponent(city); } catch (e) {}
    return { ip, country: request.headers.get('x-vercel-ip-country') || request.headers.get('cf-ipcountry') || request.cf?.country || '',
      city: city || request.cf?.city || '', ua: clean(request.headers.get('user-agent'), 300) };
  };
  try {
    const A = makeApi(env);
    const deletePhotos = async (ids) => { for (const id of ids || []) if (KEY_RE.test(id)) await A.KV.delete('photo/' + id); };

    /* ----- public ----- */
    if (route === 'public' && m === 'GET') {
      const [st, posts, links, docs] = await Promise.all([A.getJSON('status', { status: 'free' }), A.getJSON('posts', []), A.getLinks(), A.getDocs()]);
      return json({ status: st.status, posts, links, docs: docs.map(({ id, name, section, extra }) => ({ id, name, section, extra })) });
    }
    if (route === 'photo' && m === 'GET') {
      const id = url.searchParams.get('id') || '';
      if (!KEY_RE.test(id)) return new Response('Not found', { status: 404 });
      const r = await A.KV.getWithMetadata('photo/' + id, { type: 'arrayBuffer' });
      if (!r || !r.value) return new Response('Not found', { status: 404 });
      return new Response(r.value, { headers: { 'content-type': r.metadata?.type || 'image/jpeg', 'cache-control': 'public, max-age=31536000, immutable' } });
    }
    if (route === 'code' && m === 'POST') {
      const e = clean((await readJSON(request)).email, 200).toLowerCase();
      if (!EMAIL_RE.test(e)) return fail('bad_email');
      if (await A.limited('code-ip:' + ip, 10, 3600)) return fail('too_many', 429);
      const k = 'code/' + await sha(e);
      const prev = await A.getJSON(k, null);
      if (prev && Date.now() - prev.sentAt < 45 * 1000) return fail('too_many', 429);
      const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
      await A.setJSON(k, { hash: await sha(code + A.secret()), exp: Date.now() + 600000, attempts: 0, sentAt: Date.now() }, { expirationTtl: 900 });
      try {
        await A.sendMail(e, 'Your code for emilylam.hk: ' + code,
          `Your code is ${code}\n\nEnter it on emilylam.hk to keep going. It expires in 10 minutes.\n\nIf you didn't ask for this, you can ignore this email.`);
      } catch (err) { if (err instanceof SetupError) throw err; console.error(err); return fail('send_failed', 502); }
      return json({ ok: true });
    }
    if (route === 'verify' && m === 'POST') {
      const b = await readJSON(request);
      const e = clean(b.email, 200).toLowerCase(); const c = clean(b.code, 6);
      const k = 'code/' + await sha(e);
      const rec = await A.getJSON(k, null);
      if (!rec) return fail('expired');
      if (rec.exp < Date.now()) { await A.KV.delete(k); return fail('expired'); }
      if (rec.attempts >= 5) return fail('too_many', 429);
      if (!safeEqual(await sha(c + A.secret()), rec.hash)) { await A.setJSON(k, { ...rec, attempts: rec.attempts + 1 }, { expirationTtl: 900 }); return fail('bad_code'); }
      await A.KV.delete(k);
      return json({ vtoken: await A.sign({ role: 'verified', email: e }, 900) });
    }
    if (route === 'unlock' && m === 'POST') {
      const b = await readJSON(request);
      const p = await A.verify(b.vtoken, ['verified']);
      if (!p) return fail('expired');
      if (await A.limited('pw:' + p.email, 6, 900)) return fail('too_many', 429);
      const stored = (await A.getJSON('docs-password', {})).hash;
      if (!stored) return fail('no_password');
      if (!(await A.checkPw(clean(b.password, 200), stored))) return fail('bad_password');
      await logAccess(A, { email: p.email, action: 'unlocked', via: 'password' });
      await alertUnlock(A, env, p.email, 'the documents password', who());
      return json({ token: await A.sign({ role: 'viewer', email: p.email, all: true }, 86400) });
    }
    if (route === 'docs' && m === 'GET') {
      const p = await A.verify(bearer(), ['viewer']);
      if (!p) return fail('expired', 401);
      if (p.all !== true) {            // first time an approved link is opened
        const seenKey = 'grant-seen/' + await sha(bearer());
        if (!(await A.getJSON(seenKey, null))) {
          await A.setJSON(seenKey, { at: Date.now() }, { expirationTtl: 15 * 86400 });
          await logAccess(A, { email: p.email, action: 'unlocked', via: 'approved link' });
          await alertUnlock(A, env, p.email, 'the link you approved', who());
        }
      }
      const [docs, meta] = await Promise.all([A.getDocs(), A.getJSON('docs-meta', {})]);
      return json({ docs: docs.filter((d) => meta[d.id] && allowed(p, d)).map((d) => ({ id: d.id, name: d.name, section: d.section, extra: d.extra, type: meta[d.id].type })) });
    }
    if (route === 'file' && m === 'GET') {
      const p = await A.verify(bearer(), ['viewer']);
      if (!p) return new Response('This link has expired. Go back to emilylam.hk and unlock again.', { status: 401 });
      const doc = (await A.getDocs()).find((d) => d.id === url.searchParams.get('id'));
      if (!doc || !allowed(p, doc)) return new Response('Not found', { status: 404 });
      const meta = (await A.getJSON('docs-meta', {}))[doc.id];
      if (!meta) return new Response('Not found', { status: 404 });
      await logAccess(A, { email: p.email, action: 'opened', doc: doc.name, via: p.all ? 'password' : 'approved link' });
      if (meta.type === 'link') return Response.redirect(meta.link, 302);
      const data = await A.KV.get('doc-file/' + doc.id, { type: 'arrayBuffer' });
      if (!data) return new Response('Not found', { status: 404 });
      return new Response(data, { headers: {
        'content-type': meta.contentType || 'application/octet-stream',
        'content-disposition': `inline; filename="${(meta.filename || doc.id).replace(/["\\\r\n]/g, '')}"`,
        'cache-control': 'private, no-store',
      } });
    }
    if (route === 'request' && m === 'POST') {
      const b = await readJSON(request);
      if (b.bot) return json({ ok: true });
      const name = clean(b.name, 120), email = clean(b.email, 200).toLowerCase();
      const docs = await A.getDocs();
      const items = (Array.isArray(b.documents) ? b.documents : []).map(String).filter((k) =>
        (k.startsWith('doc:') && docs.some((d) => d.id === k.slice(4))) || (k.startsWith('sec:') && SECTIONS.includes(k.slice(4))));
      if (!name || !EMAIL_RE.test(email) || !items.length) return fail('bad_request');
      if (await A.limited('req-ip:' + ip, 6, 3600)) return fail('too_many', 429);
      const label = (k) => k.startsWith('doc:') ? (docs.find((d) => d.id === k.slice(4))?.name || k) : ({ portfolio: 'Portfolio', certs: 'Certificates & prizes', books: 'Books', projects: 'Science projects', main: 'Documents' })[k.slice(4)];
      const r = { id: randId(), name, email, organisation: clean(b.organisation, 160), items, documents: items.map(label),
        language: clean(b.language, 10), created: new Date().toISOString(), state: 'pending' };
      const reqs = await A.getJSON('requests', []); reqs.unshift(r); await A.setJSON('requests', reqs.slice(0, 500));
      if (env.OWNER_EMAIL) {
        try { await A.sendMail(env.OWNER_EMAIL, `Document request from ${name}`, `${name}${r.organisation ? ' (' + r.organisation + ')' : ''} <${email}> would like:\n- ${r.documents.join('\n- ')}\n\nApprove or decline: ${A.site()}/admin.html`); }
        catch (err) { console.error(err); }
      }
      return json({ ok: true });
    }

    /* ----- admin ----- */
    if (route === 'admin/login' && m === 'POST') {
      if (!env.ADMIN_PASSWORD) throw new SetupError('ADMIN_PASSWORD');
      if (await A.limited('admin-ip:' + ip, 8, 900)) { await logAdmin(A, { ok: false, reason: 'too many tries', ...who() }); return fail('too_many', 429); }
      const { password } = await readJSON(request);
      if (!safeEqual(await sha(String(password || '')), await sha(env.ADMIN_PASSWORD))) { await logAdmin(A, { ok: false, reason: 'wrong password', ...who() }); return fail('bad_password', 401); }
      const ep = (await A.getJSON('admin-epoch', { n: 0 })).n;
      const w = who(); await logAdmin(A, { ok: true, ...w });
      if (env.OWNER_EMAIL && env.RESEND_API_KEY && env.MAIL_FROM) {
        try { await A.sendMail(env.OWNER_EMAIL, 'New sign-in to your emilylam.hk admin page',
          `Someone just signed in to your admin page.\n\nWhen: ${new Date().toUTCString()}\nWhere: ${[w.city, w.country].filter(Boolean).join(', ') || 'unknown'}\nIP address: ${w.ip}\nDevice: ${w.ua || 'unknown'}\n\nIf this wasn't you, open ${A.site()}/admin.html, tap "Sign out all devices", and change ADMIN_PASSWORD in your hosting settings.`); }
        catch (err) { console.error(err); }
      }
      return json({ token: await A.sign({ role: 'admin', ep }, 7 * 86400) });
    }
    if (route.startsWith('admin/')) {
      const adm = await A.verify(bearer(), ['admin']);
      if (!adm || (adm.ep || 0) !== (await A.getJSON('admin-epoch', { n: 0 })).n) return fail('signed_out', 401);
      if (route === 'admin/signout-all' && m === 'POST') {
        const n = (await A.getJSON('admin-epoch', { n: 0 })).n + 1;
        await A.setJSON('admin-epoch', { n }); await logAdmin(A, { ok: true, event: 'signed out all devices', ...who() });
        return json({ ok: true });
      }

      if (route === 'admin/state' && m === 'GET') {
        const [st, posts, requests, links, docs, meta, pw, accessLog] = await Promise.all([A.getJSON('status', { status: 'free' }), A.getJSON('posts', []),
          A.getJSON('requests', []), A.getLinks(), A.getDocs(), A.getJSON('docs-meta', {}), A.getJSON('docs-password', {}), A.getJSON('access-log', [])]);
        const adminLog = await A.getJSON('admin-log', []);
        return json({ status: st.status, posts, requests, links, docs, meta, hasPassword: !!pw.hash, accessLog, adminLog,
          mailReady: !!(env.RESEND_API_KEY && env.MAIL_FROM), icons: ICONS, sections: SECTIONS });
      }
      if (route === 'admin/access-log' && m === 'DELETE') { await A.setJSON('access-log', []); return json({ ok: true }); }
      if (route === 'admin/status' && m === 'POST') {
        const { status } = await readJSON(request);
        if (!STATUSES.includes(status)) return fail('bad_request');
        await A.setJSON('status', { status }); return json({ ok: true });
      }
      if (route === 'admin/photo' && m === 'POST') {        // raw image bytes in the body
        const raw = await readBinary(request, MAX_PHOTO);
        const img = raw.byteLength ? stripImage(raw) : null;
        if (!img) return fail('bad_image');
        const id = randId();
        await A.KV.put('photo/' + id, img.data, { metadata: { type: img.type } });
        return json({ id });
      }
      if (route === 'admin/post' && m === 'POST') {
        const b = await readJSON(request);
        const title = clean(b.title, 160), text = clean(b.text, 8000);
        const date = /^\d{4}-\d{2}-\d{2}$/.test(b.date || '') ? b.date : new Date().toISOString().slice(0, 10);
        const photos = (Array.isArray(b.photos) ? b.photos : []).filter((x) => KEY_RE.test(x)).slice(0, 8);
        if (!title && !text && !photos.length) return fail('bad_request');
        const posts = await A.getJSON('posts', []);
        if (b.id) {
          const p = posts.find((x) => x.id === b.id); if (!p) return fail('bad_request');
          await deletePhotos((p.photos || []).filter((x) => !photos.includes(x)));
          Object.assign(p, { title, text, date, photos, edited: new Date().toISOString() });
        } else posts.unshift({ id: randId(), date, title, text, photos });
        posts.sort((a, z) => (a.date < z.date ? 1 : a.date > z.date ? -1 : 0));
        await A.setJSON('posts', posts); return json({ ok: true });
      }
      if (route === 'admin/post' && m === 'DELETE') {
        const id = url.searchParams.get('id'); const posts = await A.getJSON('posts', []);
        const p = posts.find((x) => x.id === id); if (p) await deletePhotos(p.photos);
        await A.setJSON('posts', posts.filter((x) => x.id !== id)); return json({ ok: true });
      }
      if (route === 'admin/links' && m === 'POST') {
        const { links } = await readJSON(request);
        if (!Array.isArray(links) || links.length > 20) return fail('bad_request');
        const old = await A.getLinks(); const out = [];
        for (const l of links) {
          const u = clean(l.url, 500);
          if (!/^(https:\/\/|mailto:)\S+$/.test(u) || !clean(l.label, 60)) return fail('bad_link');
          out.push({ id: /^[A-Za-z0-9_-]{1,40}$/.test(l.id || '') ? l.id : randId(), label: clean(l.label, 60), url: u, note: clean(l.note, 80),
            color: /^#[0-9a-fA-F]{6}$/.test(l.color || '') ? l.color : '#3B6D11', icon: ICONS.includes(l.icon) ? l.icon : 'link',
            ...(KEY_RE.test(l.logo || '') ? { logo: l.logo } : {}) });
        }
        const keep = new Set(out.map((l) => l.logo).filter(Boolean));
        await deletePhotos(old.map((l) => l.logo).filter((x) => x && !keep.has(x)));
        await A.setJSON('links', out); return json({ ok: true, links: out });
      }
      if (route === 'admin/docs' && m === 'POST') {
        const { docs } = await readJSON(request);
        if (!Array.isArray(docs) || docs.length > 120) return fail('bad_request');
        const out = []; const seen = new Set();
        for (const d of docs) {
          const id = DOC_ID_RE.test(d.id || '') ? d.id : 'doc-' + hex(crypto.getRandomValues(new Uint8Array(5)));
          if (seen.has(id) || !clean(d.name, 160) || !SECTIONS.includes(d.section)) return fail('bad_request');
          seen.add(id); out.push({ id, name: clean(d.name, 160), section: d.section, ...(clean(d.extra, 20) ? { extra: clean(d.extra, 20) } : {}) });
        }
        const old = await A.getDocs(); const meta = await A.getJSON('docs-meta', {});
        for (const d of old) if (!seen.has(d.id)) { delete meta[d.id]; await A.KV.delete('doc-file/' + d.id); }
        await A.setJSON('docs-meta', meta); await A.setJSON('docs', out); return json({ ok: true, docs: out });
      }
      if (route === 'admin/password' && m === 'POST') {
        const pw = String((await readJSON(request)).password || '');
        if (pw.length < 6) return fail('too_short');
        await A.setJSON('docs-password', { hash: await A.hashPw(pw), updated: new Date().toISOString() }); return json({ ok: true });
      }
      if (route === 'admin/doc-link' && m === 'POST') {
        const { id, link } = await readJSON(request);
        if (!(await A.getDocs()).some((d) => d.id === id) || !/^https:\/\/\S+$/.test(String(link || ''))) return fail('bad_request');
        const meta = await A.getJSON('docs-meta', {});
        meta[id] = { type: 'link', link: String(link), updated: new Date().toISOString() };
        await A.KV.delete('doc-file/' + id); await A.setJSON('docs-meta', meta); return json({ ok: true });
      }
      if (route === 'admin/doc-file' && m === 'POST') {     // raw file bytes in the body; ?id=&name=
        const id = url.searchParams.get('id');
        if (!(await A.getDocs()).some((d) => d.id === id)) return fail('bad_request');
        let data = await readBinary(request, MAX_FILE);
        if (!data.byteLength) return fail('bad_request');
        const contentType = clean(request.headers.get('content-type'), 100) || 'application/octet-stream';
        const img = /^image\/(jpeg|png)$/.test(contentType) ? stripImage(data) : null;
        if (img) data = img.data;
        await A.KV.put('doc-file/' + id, data);
        const meta = await A.getJSON('docs-meta', {});
        meta[id] = { type: 'file', filename: clean(url.searchParams.get('name'), 160) || id, contentType, size: data.byteLength, updated: new Date().toISOString() };
        await A.setJSON('docs-meta', meta); return json({ ok: true });
      }
      if (route === 'admin/doc' && m === 'DELETE') {
        const id = url.searchParams.get('id');
        const meta = await A.getJSON('docs-meta', {}); delete meta[id];
        await A.KV.delete('doc-file/' + id); await A.setJSON('docs-meta', meta); return json({ ok: true });
      }
      if (route === 'admin/request' && m === 'POST') {
        const { id, action } = await readJSON(request);
        const reqs = await A.getJSON('requests', []);
        const r = reqs.find((x) => x.id === id);
        if (!r || !['approve', 'decline'].includes(action)) return fail('bad_request');
        if (action === 'approve') {
          const items = r.items || [];
          const grant = { role: 'viewer', email: r.email, docs: items.filter((k) => k.startsWith('doc:')).map((k) => k.slice(4)), sections: items.filter((k) => k.startsWith('sec:')).map((k) => k.slice(4)) };
          const link = `${A.site()}/#unlock?grant=${await A.sign(grant, 14 * 86400)}`;
          try {
            await A.sendMail(r.email, 'Emily shared her documents with you',
              `Hi ${r.name},\n\nEmily approved your request for: ${r.documents.join(', ')}.\n\nOpen them here (the link works for 14 days):\n${link}\n\nEmily can see which documents are opened with this link.\n\nEmily Lam\nemilylam.hk`);
          } catch (err) { if (err instanceof SetupError) throw err; console.error(err); return fail('send_failed', 502); }
          r.state = 'approved';
        } else r.state = 'declined';
        r.decided = new Date().toISOString();
        await A.setJSON('requests', reqs); return json({ ok: true });
      }
    }
    return fail('not_found', 404);
  } catch (err) {
    if (err instanceof SetupError) { console.error('Missing setting:', err.message); return json({ error: 'setup', missing: err.message }, 500); }
    if (err instanceof HttpError) return fail(err.code, err.status);
    console.error(err); return fail('server', 500);
  }
}
