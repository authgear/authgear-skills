# Deploy target: Cloudflare

## Read before deploying (always use the current docs)

- Static SPA on Workers (Cloudflare's current recommendation for new static sites):
  https://developers.cloudflare.com/workers/static-assets/ and the SPA routing section
  https://developers.cloudflare.com/workers/static-assets/routing/single-page-application/
- Vite on Workers (Cloudflare's Vite plugin): https://developers.cloudflare.com/workers/vite-plugin/
- React framework guide: https://developers.cloudflare.com/workers/framework-guides/web-apps/react/
- Wrangler CLI and config: https://developers.cloudflare.com/workers/wrangler/
- Custom domains: https://developers.cloudflare.com/workers/configuration/routing/custom-domains/
- Response headers for static assets (`_headers`): https://developers.cloudflare.com/workers/static-assets/headers/
- Pages is still supported: https://developers.cloudflare.com/pages/. Use it only if the user already uses Pages,
  or asks for it.

Follow what those pages say today: config file format, the SPA fallback setting, and the deploy command.

## Requirements

1. **SPA fallback.** Unknown paths (`/login`, `/signup`, `/oauth-callback`, `/reset-password`, …) must serve `index.html`.
   On Workers static assets, this is the single-page-application `not_found_handling` setting. Verify a direct hit
   on `/login?...` after deploying.
2. **Build-time env.** `VITE_*` values are inlined at build time. Set `VITE_AUTHGEAR_ENDPOINT` (and the others)
   in `.env.production`, or in the CI build environment. Runtime Worker vars/secrets do **not** reach the static bundle.
3. **Auth.** The user runs `npx wrangler login` themselves; suggest `! npx wrangler login`. Never ask for their API token in chat.
   For CI, point them to the docs for `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID`.
4. **Name.** Use the project name the user gave (`projectName` in the manifest) as the Worker name. Don't invent one.
   If Cloudflare rejects it (naming rules or already taken), ask the user for another name.
5. **Confirm before the first deploy.** It publishes to the user's account and creates a public URL.
6. **Headers** (via `_headers` or the documented mechanism):
   - `Content-Security-Policy` with `connect-src 'self' <authgear endpoint> wss://<authgear host>`, the bot-protection
     domains if they're used, and `frame-ancestors 'none'`.
   - `Cache-Control: no-cache` for `index.html`. Hashed `/assets/*` can be cached long.
7. **Domain choice.** Ask before deploying:
   - `*.workers.dev` is fine for a first test. It is **cross-site** with Authgear; see SKILL.md → Cross-site limitations,
     and warn the user if the YAML uses any of those features.
   - For production, recommend a custom domain on the **same registrable domain** as the project's Authgear
     custom domain (e.g. UI `login.example.com`, Authgear `auth.example.com`). If passkeys are used in browsers, it
     must be a subdomain of the Authgear host instead (e.g. `login.auth.example.com`). The zone must be on Cloudflare.
   - If the user chose to support Apple sign-in with a POST callback route, the deploy needs a Worker script (not assets only).
8. **After deploying:** update the client's Custom UI URI in the Authgear Portal to `https://<deployed host>/login`
   (or whichever route is the entry). Add `https://<deployed host>/oauth-callback` to each OAuth provider's console.
   Then smoke-test via the authorize URL.
9. Record the deployed URL and the Worker/project name in `.authgear/manifest.json` (`deploy.url`, `deploy.name`),
   so update runs can redeploy without asking again.
