# Implementation rules for a browser-side Custom UI

These rules apply whatever the framework. For input/output shapes, fetch the upstream sources
listed in `authflow-api.md`.

## 1. Runtime model: the browser calls Authgear directly

- The Custom UI is static files. The only exception is an Apple POST callback route, if the user chose to add one. Every API call is
  `fetch(url, { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body })`.
- **CORS.** Authgear allows a cross-origin call only when the caller's origin
  matches the origin of some OAuth client's `x_custom_ui_uri`, or appears in `http.allowed_origins`. If CORS isn't
  configured, *every* call fails with a bare `TypeError: Failed to fetch`. Catch network errors
  and show a developer hint: "Is this origin registered as the client's Custom UI URI?"
- The Authgear endpoint is a public build-time setting, e.g. `VITE_AUTHGEAR_ENDPOINT`. It isn't
  a secret. Read it through one config module. Strip any trailing `/`.
- **No secrets in the bundle.** Nothing in the browser needs a client secret or an Admin API key.
- `credentials: "include"` is the only correct way to send cookies. Browsers forbid setting a
  `Cookie` header manually.

## 2. Entry: keep the authorization query

Authgear redirects to the Custom UI URI with a query such as
`?x_ref=…&client_id=…&redirect_uri=…&state=…&ui_locales=…&x_settings_action_id=…`. `x_ref` is the OAuth
session reference: the value of `queryNameOAuthSessionID` in `pkg/lib/oauth/oidc/ui.go`. The full list is set in
`addToEndpoint` / `BuildAuthenticationURL` in the same file. Read the string values there, not the Go identifiers.
Treat the query as opaque and forward all of it.

- On first load, save `window.location.search` (without `?`) as `urlQuery`. Store it in
  `sessionStorage` too, so it survives the OAuth round trip and full reloads.
- Send `url_query: urlQuery` in the body of **every create** request. Don't append it to the create URL.
- Links between entry pages (`/login` ↔ `/signup` ↔ `/forgot-password`) must keep the query.
- If a page loads with **no** `x_ref`/`client_id` and nothing in storage, the flow
  can't finish. Show a "Start sign-in from your app" message instead of a form. In development,
  also show how to build a test authorize URL.
- `ui_locales`: use it to choose the UI language, if the UI is localized.
- `login_hint`: if present and it is a plain login ID, prefill the identifier field.
- `id_token_hint`: if present and the build supports reauthentication, create the `reauth` flow instead of `login`
  (SKILL.md → Reauthentication).
- `x_color_scheme`: honour `light`/`dark` if the UI supports themes.

## 3. Flow state and navigation

- Model the UI as **"render the current `result`"**. A single runner holds the latest result and
  exposes `submit(input)`. A screen component is chosen by
  `action.type` → `data.type` → `identification`/`authentication`.
- Push each new result onto the navigation history: put the `state_token` (and the result, or enough
  to re-render it) in the history entry's state, or in a URL search param. Then Back re-renders the
  earlier state, and submitting from it branches correctly. The API is built for this.
- On reload, re-read the current state with `POST /states` using the stored token. Don't recreate the flow.
- **Pre-create flows on page load** (call create with no input) and render the `identify` options
  from the response. Don't hardcode them. This is what makes `select_account` and the OAuth
  buttons (aliases and providers come from the server) appear.
- Disable submit while a request is in flight. Guard against double-submits, and against React StrictMode
  double effects creating two flows.
- When `action.type === "finished"`, set `window.location.href = data.finish_redirect_uri` and
  `return`. Assigning to `href` doesn't stop execution by itself. If there is no `finish_redirect_uri`
  (possible for account recovery started without an OAuth session), show a success screen.
- **Unsupported step fallback.** If a response has an action that isn't in the screen plan, render a
  clear error. In dev builds include `action.type`/`data.type`. Log the whole result to the console.

## 4. The `signup_login` hand-off

A `signup_login` flow starts with an identify step. After the identifier input, the result's `type`
becomes `signup` or `login`, depending on whether the identity exists. The UI doesn't decide this.
Keep dispatching on `action`. You may change the heading ("Create your account" vs "Welcome
back") based on `result.type`.

## 5. OAuth providers

1. Submit `{ identification: "oauth", alias, redirect_uri: origin + "/oauth-callback" }`.
2. Save the returned `state_token` in `sessionStorage` (e.g. `authgear.oauth.state_token`). Also save the
   `urlQuery` and the entry route, so the callback can recover from errors.
3. `window.location.href = data.oauth_authorization_url`.
4. On `/oauth-callback`: read the saved token and submit `{ query: window.location.search.slice(1) }`.
   Clear the storage. Dispatch the result normally: it can be `finished`, or more steps
   (account linking, `create_authenticator`, 2FA, `fill_form`, …).
5. The provider's own console must list `https://<ui-origin>/oauth-callback` (and the local dev
   URL) as an authorized redirect URI. This is the Custom UI URL, **not** Authgear's `/sso/oauth2/callback/<alias>`.
6. Guard the callback against running twice (StrictMode, reloads). The authorization code is single-use.
7. Apple: Apple POSTs the callback (`form_post`). Implement whatever the user chose in step 2 (see the `authflow-api.md` errata).

## 6. OTP code and link screens

- Show `masked_claim_value` / `masked_display_name`. Use one input with
  `inputmode="numeric" autocomplete="one-time-code"`, with `maxlength` set to `code_length`. Auto-submit
  when the code is complete, if you like.
- **Resend cooldown.** Read `data.can_resend_at` and render "Resend in 23s". Enable the button when
  the time is reached. After a resend, take the new `can_resend_at` from the response. One shared
  `useCountdown(targetISO)`-style helper serves resend and lockout alike.
- Link form (`otp_form: "link"`) for login/verify: show "Check your inbox". Open `data.websocket_url` and, on any message,
  `POST /states`. If `can_check` is now true, submit `{ check: true }`. Also poll every few seconds as a fallback,
  and show an "I've clicked the link" button. Close the socket when the screen unmounts. The link itself is approved on
  Authgear's page; there's no API to approve it from the Custom UI. (Auth UI's `authflow_websocket.ts` /
  `authflow_polling.ts` show the same pattern.)
- **Recovery link opening the Custom UI** (only if the user customizes the email template; see `authflow-api.md` errata):
  1. The user changes the forgot-password email/SMS link to e.g. `https://<ui>/reset-password?code={{ .Code }}`.
     The template customization is done by the user in their Authgear project; tell them exactly what to change.
  2. `/reset-password` reads `code` and POSTs `{ "input": { "account_recovery_code": code } }` with **no `state_token`**.
  3. Render `reset_password`, then show success when `finished` arrives with no `finish_redirect_uri`. The link may be
     opened in another browser or device, so this page must not depend on `sessionStorage`.
  4. On the original tab, the `verify_account_recovery_code` link screen just says "check your inbox" (with resend).

## 7. Passwords

- New password fields: render rules from `password_policy` as a live checklist. Add a confirm field
  that is checked on the client only. Set `autocomplete="new-password"`.
- Login password: `autocomplete="current-password"`. Put the identifier field before it
  with `autocomplete="username"` (or `email`/`tel`), so password managers pair them.
- A single login form may submit identifier + password with `batch_input`, but only when the YAML
  offers exactly one authenticate option after that identification. Even then, dispatch the result.
  It may be 2FA, `change_password`, `terminate_other_sessions`, `fill_form` or `prompt_create_passkey`.

## 8. Passkeys (WebAuthn)

- **Domain constraint.** Authgear sets the WebAuthn `rpId` to **its own hostname**. It accepts
  ceremonies from Custom UI origins (any client's `x_custom_ui_uri` origin is an allowed RP origin),
  but the **browser** rejects an `rpId` that isn't the page's host or a parent domain of it. The UI therefore
  has to be on Authgear's host or a subdomain of it; a sibling subdomain isn't enough (`docs/specs/webauthn.md`).
  Inside a native app's WebView, `x_native_apps` applies instead (`docs/specs/passkey-webview.md`). Confirm the
  domain plan with the user before building passkey screens (see flow-config.md checklist).
- Reference implementation in TypeScript: Auth UI's `authui/src/passkey.ts` in authgear-server.
- Request (sign-in): use `PublicKeyCredential.parseRequestOptionsFromJSON(option.request_options.publicKey)`
  where supported, then `navigator.credentials.get({ publicKey })`. Otherwise convert the base64url fields
  (`challenge`, `allowCredentials[].id`) to `ArrayBuffer` by hand.
- Response: use `credential.toJSON()` where supported. Otherwise serialize these as base64url (no padding):
  `{ id, rawId, type, response: { clientDataJSON, authenticatorData, signature, userHandle? }, clientExtensionResults }`.
  Send it as `assertion_response`.
- Creation (`prompt_create_passkey`): the same idea with `parseCreationOptionsFromJSON(creation_options.publicKey)`
  / `navigator.credentials.create`. Send
  `creation_response: { id, rawId, type, response: { attestationObject, clientDataJSON, transports }, clientExtensionResults }`.
- The spec's reference JS (base64 helpers plus `serializeAssertionResponse` / `serializeAttestationResponse`) is in
  `docs/specs/authentication-flow-api-reference.md` (sections `primary_passkey` and `prompt_create_passkey`).
  Port it to TypeScript when the JSON helpers aren't available. Check current browser support for
  `parse*OptionsFromJSON` / `toJSON` on MDN.
- Treat `NotAllowedError` (the user cancelled) as a quiet "try again" message, not as an error.

## 9. Bot protection

If any reachable option has `bot_protection`:
- Load the provider widget for `bot_protection.provider.type`:
  `cloudflare` → Cloudflare Turnstile; `recaptchav2` → Google reCAPTCHA v2. Read the provider's current
  docs for the script URL and the explicit-render API.
- Make the **site key** a build-time setting (e.g. `VITE_BOT_PROTECTION_SITE_KEY`). Get it from the user's
  `authgear.yaml` (`bot_protection.provider.site_key`).
- Add `bot_protection: { type, response: token }` to that option's input. Reset the widget after
  every submit, because tokens are single-use.

## 10. TOTP enrollment and recovery codes

- TOTP: render a QR code of `otpauth_uri`. Use a small, maintained QR library; look up the current
  choice. Show `secret` with a copy button for manual entry.
- Recovery codes: show them in a monospace grid, with "Copy" and "Download .txt". Enable "Continue" only after
  an "I have saved these codes" checkbox.

## 11. Forms (`fill_form`, identify `form`)

Render `form.fields` in order. The field `type` → value → control table is in the API reference spec,
section "fill_form_data". Render each field
from the response: `label`, `required`, `constraints`, `options`, `value`. Only the field types
the YAML can produce need components. Show server field errors next to their fields.

## 12. Security hygiene

- Never render `error.message` or raw server text as HTML. The only exception is boolean form labels, which
  may contain `<a href>`; sanitize those to allow-list `<a href>` only.
- `finish_redirect_uri` and `oauth_authorization_url` come from Authgear. Navigate to them as given.
  Never take a redirect target from the Custom UI's own query string.
- Set a sensible CSP and `frame-ancestors 'none'` (or `X-Frame-Options: DENY`) at the host, to prevent
  click-jacking. Permit only the Authgear endpoint in `connect-src`, plus `wss:` for link OTP, plus any
  bot-protection domains. The deploy reference covers this.
- Don't store passwords, OTP codes or recovery codes anywhere. Keep only `state_token`, `urlQuery` and the
  OAuth state, in `sessionStorage`.

## 13. Copy and UX defaults

- One primary action per screen. Show "Back" when there is a previous state.
- Masked destinations: "We sent a 6-digit code to jo\*\*\*@example.com".
- Account-recovery identify: use neutral wording that doesn't confirm the account exists.
- Show a loading state while the flow is created.
- Mobile-first layout, labelled inputs, visible focus, and errors linked to their fields with `aria-describedby`.
