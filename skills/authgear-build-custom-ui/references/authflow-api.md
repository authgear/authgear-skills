# Authentication Flow API: where to read, and what the docs get wrong

Don't work from memory or from a copy. **Fetch the upstream sources** below before you
implement a screen. Fetch the raw URLs with your web-fetch tool. This file only maps
*where* each fact lives, and lists the places where the spec and the actual server behaviour differ.

Base: `https://raw.githubusercontent.com/authgear/authgear-server/main/`

## Source map

| Need | Read |
|------|------|
| Endpoints, response envelope, every `action.type` and its `data` and input | `docs/specs/authentication-flow-api-reference.md` |
| Concepts, branching, state tokens | `docs/specs/authentication-flow.md` |
| **Exact input schema** for each step (authoritative when the spec is unclear) | `pkg/lib/authenticationflow/declarative/input_*.go`. Browse the list at https://github.com/authgear/authgear-server/tree/main/pkg/lib/authenticationflow/declarative |
| Create-request body (`type`, `name`, `url_query`, `batch_input`) | `pkg/auth/handler/api/authenticationflow_v1_create.go` |
| Response `data.type` values | `pkg/lib/authenticationflow/declarative/data_type.go`, and the `data_*.go` files beside it for field names |
| Identify / authenticate option fields | `pkg/lib/authenticationflow/declarative/data_*option*.go`, and `IdentificationOption` in the same package |
| `select_account` (SSO continuation) | `docs/specs/custom-ui-select-account.md` |
| `fill_form` / profile forms | `docs/specs/user-profile/profile-filling.md` |
| Query params Authgear appends to the Custom UI URI | `addToEndpoint` and `BuildAuthenticationURL` in `pkg/lib/oauth/oidc/ui.go` |
| Passkeys: rules for a Custom UI page, and passkeys in native-app WebViews | `docs/specs/webauthn.md` ("It may claim the Relying Party ID", "Its origin is accepted"), `docs/specs/passkey-webview.md` |
| **How Authgear's own Auth UI does it in the browser** (TypeScript; reference only, it's Stimulus/Turbo, not React) | `authui/src/`: `passkey.ts` (WebAuthn (de)serialization, autofill), `authflow_websocket.ts` + `authflow_polling.ts` (link OTP), `countdown.ts` / `resendButton.ts`, `password-policy.ts`, `authflowv2/botprotection/` (Turnstile / reCAPTCHA) |

When reading Go source, take wire names from **string literals and `json:"…"` tags**, never from
Go identifiers. For example, the constant `queryNameOAuthSessionID` has the value `"x_ref"`.

Map a step to its input file by name, e.g. `authenticate` → `input_login_flow_step_authenticate.go`,
identify → `input_step_identify.go`, OTP → `input_node_verify_claim.go` / `input_node_auth_oob.go`,
`create_authenticator` → `input_signup_flow_step_create_authenticator.go`, terminate sessions →
`input_confirm_terminate_other_sessions.go`, passkey → `input_take_passkey_assertion_response.go`.

## Errata and gotchas (verified against source, Nov 2026; re-check if in doubt)

- **Forward the authorization query in the request body:**
  `{ "type", "name", "url_query": "<the Custom UI's raw query string, without '?'>" }`. Use this
  convention in every generated UI.
  (For reference: the handler would also find the OAuth session from `x_ref` in the create URL's own query,
  via `GetOAuthSessionID`. But `client_id`, `state`, `x_state`, `ui_locales` and `login_hint` are read
  only from the body by `makeSessionOptionsFromQuery`, and that is the only source when there is no `x_ref`, e.g. a
  forgot-password flow opened directly. So the body covers every case.)
- **OTP resend is just `{ "resend": true }`.** No `authentication` field is needed. Link approval check is `{ "check": true }`.
- **The OAuth callback input is `{ "query": "<callback query string>" }`.** `code` isn't part of the schema.
  Send the query even when it contains `error=`.
- **OOB authenticate inputs need `index`** (the position in the full `options` array). They need `channel` **only when the
  option lists more than one channel**.
- **`create_authenticator` OOB inputs need `target` only when the option has no `target`**
  (no `target_step`). The schema has no `channel` key, despite the spec example. Channel choice comes later as
  `select_oob_otp_channels_data`.
- **`reset_password` returns `data.type: new_password_data`** (the spec says `reset_password_data`).
  `change_password` uses the same data type plus `force_change_reason` (`policy` / `expiry`).
  Dispatch on `action.type` first.
- **Steps that are in the config schema but missing from the API reference:**
  - `terminate_other_sessions`. Input `{ "confirm_terminate_other_sessions": true }`.
  - `check_account_status`. Never takes input; either passes or errors (`DisabledUser`, …).
  - Identification `passkey`. Input `{ identification: "passkey", assertion_response }`.
  - `recovery_code`. Input `{ authentication: "recovery_code", recovery_code }`.
  - `request_device_token: true` on authenticate inputs when `data.device_token_enabled`.
- **Emailed links point to Authgear's own pages by default** (`pkg/lib/authn/otp/sender.go`).
  The message templates can be customized to point at the Custom UI instead (template variables: `Code`, `URL`,
  `Link`, `Host`).
  - **Recovery links can be handled by the Custom UI.** Point the forgot-password template's link at e.g.
    `https://<ui>/reset-password?code={{ .Code }}`. On that page, POST `/states/input` with
    `{ "input": { "account_recovery_code": "<code>" } }` and **no `state_token`**. The server creates a new
    recovery flow from the code (`resolveStateTokenFromInput` in `pkg/lib/authenticationflow/service.go`). Continue
    with `reset_password` → `finished`. There's no OAuth session, so expect no `finish_redirect_uri`: show success and a link to the app.
    Templates: `resources/authgear/templates/en/messages/forgot_password_email.*` (+ `_sms`), and the
    `ForgotPasswordEmailTXT` / `ForgotPasswordSMSTXT` keys in `translation.json`.
  - **Magic login links (`*_login_link`) can't be approved from a Custom UI.** Approval exists only in the Auth UI
    handler `pkg/auth/handler/webapp/authflowv2/verify_login_link.go`. (The `pkg/latte` workflow intents are legacy;
    never use them.) Keep those links on Authgear's page; the Custom UI waits with the websocket/`check`.
- **Passkeys.** The Relying Party ID is the host of `http.public_origin`. The rules are in `docs/specs/webauthn.md`:
  - **In a browser,** the page must be on that host or a subdomain of it. Same-site is not enough: with Authgear at
    `auth.example.com`, `ui.auth.example.com` works and `ui-b.example.com` doesn't. The Custom UI's origin must also be
    registered as the client's `x_custom_ui_uri`.
  - **In a native app's WebView,** passkeys work for a Custom UI too, if the app is listed in the client's
    `x_native_apps` (`docs/specs/passkey-webview.md`). Authgear then serves `/.well-known/apple-app-site-association`
    and `assetlinks.json` (`pkg/auth/handler/wellknown/association_files.go`), but **only on a custom domain**.
  - `credential.toJSON()` output satisfies the assertion schema, which allows extra properties.
- **Apple sign-in needs a POST callback.** Apple is standard OAuth/OIDC, but with one Apple-specific rule: when
  the request asks for scopes, Apple requires `response_mode=form_post`. Authgear always asks Apple for `name email`
  (`pkg/lib/oauthrelyingparty/apple/provider.go`). So Apple returns to `redirect_uri` with an HTML form **POST**, not
  a GET with a query string, and static files can't receive a POST. Send `response_mode: "form_post"` on the oauth
  input, and add a tiny server route at the Custom UI's host that turns the POST body into a redirect to
  `/oauth-callback?<body>`; on Cloudflare, that's a Worker script alongside the static assets. Authgear's own Auth UI
  doesn't hit this because its callback is server-side. Confirm the rule against Apple's current docs. Other providers
  use the default (query) mode.
  **Don't decide this yourself.** When Apple sign-in is reachable, explain the limitation to the user and let them
  choose: add the server route, drop Apple from this Custom UI, or another approach they prefer. Record the decision
  in `flow-map.md`.
- **Cookies only matter at the end of a flow.** Flow state is server-side, keyed by `state_token`. When the flow
  finishes, the Authgear session cookie (and the device-token cookie) is set on the `fetch` response, which is why
  some features don't work cross-site. See SKILL.md → Cross-site limitations.
- **Websocket (link OTP)** accepts the same origins as CORS (`pkg/auth/handler/api/authenticationflow_v1_websocket.go`).
- **Reauthentication.** Authgear forwards `id_token_hint` (and `login_hint`) to the Custom UI, but not `prompt`
  (`BuildAuthenticationURL` in `pkg/lib/oauth/oidc/ui.go`). See SKILL.md → Reauthentication.
- **The built-in `tester` client never reaches a Custom UI.** It's constructed with no `x_custom_ui_uri`
  (`pkg/lib/tester/client.go`, `pkg/lib/oauthclient/resolver.go`), and its redirect URI is Authgear's own `/tester` page.
  Test with an SPA or Native client that has the Custom UI URI (SKILL.md step 5).
- **CORS allow-list.** It is every client's `x_custom_ui_uri` origin plus `http.allowed_origins`
  (`pkg/lib/infra/middleware/cors_matcher.go`).
- **Flow allowlist.** If the client sets `x_authentication_flow_allowlist`, only the listed flows can be created.
  See `docs/specs/authentication-flow-selection.md`.
