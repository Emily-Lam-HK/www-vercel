# emilylam.hk — Vercel version

- `public/` — the website, the booking loading page (`public/meet/`), your admin page (`admin.html`)
- `api/router.js` + `lib/core.js` — the backend (Log, status, links, documents, unlock, requests)
- `vercel.json` — tells Vercel where things are, sends meet.emilylam.hk to the booking page

## Common mistakes
- Unzip first, then upload **what's inside** the folder (so `vercel.json` sits at the top of the repo).
- Don't upload a `node_modules` folder if one appears.

## 1. Put it on Vercel
1. **GitHub:** new repository → "uploading an existing file" → drag in everything from this folder → Commit.
2. **Vercel:** Add New → Project → Import that repository.
   Framework Preset **Other**, leave Build Command empty. Click **Deploy**.

## 2. Add storage (both free)
In your Vercel project → **Storage**:
1. **Create → Upstash for Redis** (from the Marketplace) → connect it to this project.
   This stores your posts, links, status, documents list and requests.
2. **Create → Blob** → choose **Private** → connect it to this project.
   This stores your photos and document files.
Vercel adds their connection settings for you.

## 3. Add your settings
Project → **Settings → Environment Variables** (all environments):
| Name | Value |
|---|---|
| `ADMIN_PASSWORD` | the password for your admin page — you choose it |
| `SESSION_SECRET` | any long random text, 40+ characters |
| `RESEND_API_KEY` | your key from resend.com (for the 6-digit codes) |
| `MAIL_FROM` | `Emily Lam <me@emilylam.hk>` |
| `OWNER_EMAIL` | `me@emilylam.hk` |
| `SITE_URL` | `https://emilylam.hk` |

Then **Deployments → ⋯ → Redeploy** (settings only apply to new deployments).

## 4. Domains
Project → **Settings → Domains**: add `emilylam.hk` and `meet.emilylam.hk`, then add the DNS records
Vercel shows wherever your domain's DNS is managed. Delete the old `meet` forwarding first.
meet.emilylam.hk opens the booking loading page automatically.

## 5. Email codes (Resend)
resend.com → Domains → Add `emilylam.hk` → add the DNS records it shows → Verify → API Keys → Create.
Paste the key into `RESEND_API_KEY` and redeploy.

## Everyday use — emilylam.hk/admin.html
Log in with `ADMIN_PASSWORD`. Set your status, write Log posts with photos (location and camera details
are removed), edit links and their QR colours/logos, manage locked documents and the documents password
(this is what visitors type after their email code), and approve requests.
