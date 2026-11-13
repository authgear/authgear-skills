---
name: authgear-build-custom-ui
description: Build, update, and deploy a Custom UI (custom login/signup/forgot-password pages) for Authgear driven by the Authentication Flow API (authflow). Use when the user wants to "build a custom UI for Authgear", "replace the Authgear login page", "create custom login/signup pages from my authentication_flow config", "implement authflow", provides the `authentication_flow` section of an authgear.yaml, asks to update an existing Custom UI after changing that YAML, or wants to deploy a Custom UI (e.g. to Cloudflare). Runs in any directory — it scaffolds a new project or updates one it generated earlier.
---

# Authgear Custom UI

Builds a Custom UI web app that talks to Authgear's **Authentication Flow API**
for exactly the flows described in the user's `authentication_flow` YAML, then
deploys it. When the user later changes the YAML, the same skill diffs it
against what was built and updates only what changed.

How it works end-to-end:

```
User's app → Authgear /oauth2/authorize?client_id=…
  → Authgear redirects the browser to the client's Custom UI URI (x_custom_ui_uri) with the
    authorization query appended (x_ref, client_id, redirect_uri, state, ui_locales, …)
  → Custom UI creates a flow: POST {endpoint}/api/v1/authentication_flows {type, name, url_query}
  → Custom UI renders whatever action the response asks for, POSTs input to /states/input, repeats
  → action.type == "finished" → window.location.href = action.data.finish_redirect_uri
    (account_recovery is created without x_ref, so it finishes with no finish_redirect_uri and shows a
     success screen; see ui-implementation.md §3)
  → Authgear completes OIDC and redirects back to the user's app
```

## Principles

- **Build for the YAML you are given, not for every possible YAML.** Only implement
  the steps, identifications and authentications that the user's flows can reach.
  Keep the code simple and readable; don't build a generic engine.
- **The server response is authoritative at runtime.** The YAML tells you which
  screens to build; at runtime, always dispatch on the response's `action.type`,
  `action.data.type`, `action.identification` / `action.authentication` and the
  `options` array — never assume the next step from the YAML alone (e.g. `optional`
  authenticate steps, 2FA the user hasn't enrolled, `change_password` when not due,
  and `account_linking` can add or skip screens).
- **Don't use a canned template. Look up the current way to scaffold.** Before
  scaffolding or deploying, read the official docs on the web (Vite, React,
  Cloudflare, …) and use their current recommended commands and config.
  The framework and deploy references here list *what must be true*; the
  live docs decide *how* to set it up today.
- **Always read the upstream sources; never work from a copy.** The references in this skill
  *link* to authgear-server's specs and source code (raw GitHub URLs), so you always read the
  latest version. Fetch the linked files before implementing. The references only add what
  upstream doesn't say: the workflow, the review checklist, and errata where the spec and the
  server disagree. If an erratum no longer matches upstream, trust upstream.
  Key sources:
  - API reference: https://raw.githubusercontent.com/authgear/authgear-server/main/docs/specs/authentication-flow-api-reference.md
  - Flow concepts: https://raw.githubusercontent.com/authgear/authgear-server/main/docs/specs/authentication-flow.md
  - Config JSON schema: https://raw.githubusercontent.com/authgear/authgear-server/main/pkg/lib/config/authentication_flow.go
  - Input schemas: https://github.com/authgear/authgear-server/tree/main/pkg/lib/authenticationflow/declarative (`input_*.go`)

## Workflow

### 0. Detect mode: new project or update

Look for a `.authgear/manifest.json` file in the current directory, or one level
down, whose `"skill"` is `"authgear-build-custom-ui"`. (The skill writes this file on its first run; see step 6.)
If several projects match, ask the user which one to update.

- **Found** → **Update mode**. Go to [Updating an existing Custom UI](#updating-an-existing-custom-ui).
- **Not found** → **New project mode**. Continue with step 1.

### 1. Collect inputs

**a. The YAML (required).** Ask for the `authentication_flow` section of their
`authgear.yaml`, either as a file path or pasted. Accept either the bare section
(`login_flows:` …) or a full config containing `authentication_flow:`. If they
also have `ui.authentication_flow.groups` / `oauth.clients[].x_authentication_flow_allowlist`,
ask for those too. An allowlist limits which flow names this client may create.

How the user got the YAML doesn't matter (e.g. their config repo, or exporting the config from the Portal).
Just ask them to provide it.

Some runtime behaviour is set **outside** `authentication_flow`. Ask for these sections too, if the user can share
them (or ask the questions directly). Never ask for secrets.
- `authenticator.oob_otp.email.email_otp_mode`: `login_link` makes email login OTP a magic **link** instead of a code.
- `authentication.secondary_authentication_grace_period`: during a 2FA grace period, a login `authenticate` step can
  turn into 2FA **enrollment** (`create_authenticator` screens).
- Top-level `bot_protection` (`enabled`, `provider.type`, `provider.site_key`): bot protection only applies when this is enabled.
- `identity.oauth.providers` (each `alias`, `type` and `credentials_behavior`): the YAML only says `identification: oauth`.
  This section tells you which providers exist, including whether Apple is used (see the Apple erratum), and which provider
  consoles need the callback URL.
- Top-level `account_linking`: whether signup can turn into "sign in to link this account" screens (the default action is `error`).
- `authenticator.password.force_change`: when false, `change_password` appears only for expired passwords, not for
  policy changes (`intent_login_flow_step_change_password.go`).
- If an entry flow is named `default` but **isn't defined** in the YAML, the server generates it from `identity`,
  `authentication`, `authenticator`, `verification`, `bot_protection` and `ui.forgot_password` (`generate_config_*.go`).
  Ask for those sections, or describe the flow back to the user and get it confirmed (see `references/flow-config.md`).

Also ask whether their app uses **reauthentication** (asking a signed-in user to confirm their identity again,
e.g. the SDK's `reauthenticate`). If it does, the Custom UI must also handle the `reauth` flow; see
[Reauthentication](#reauthentication).

**b. Framework.** Use AskUserQuestion. Today there is one option. Keep the question
anyway so more frameworks can be added later:

```json
{
  "questions": [{
    "question": "Which framework should the Custom UI use?",
    "header": "Framework",
    "multiSelect": false,
    "options": [
      { "label": "React (SPA)", "description": "Client-side React app built with Vite. No server; static files call the Authentication Flow API from the browser. Not Next.js." }
    ]
  }]
}
```

The reference for each framework is in `references/frameworks/`: React SPA → `references/frameworks/react-spa.md`.

**c. Deployment target.** Use AskUserQuestion. Today: **Cloudflare**. Add more options here when more targets are supported, e.g. Vercel.
→ `references/deploy/cloudflare.md`.

**Prerequisite: Custom UI must be enabled for the project.** It's a plan feature (`oauth.client.custom_ui_enabled`,
default `false`, in `pkg/lib/config/feature_oauth.go`). When it's off, saving any `x_custom_ui_uri` fails with
"custom ui is disallowed". Ask the user to confirm their plan allows it before building anything.

**d. Project details.** Ask for or confirm these:
- Authgear endpoint, e.g. `https://myproject.authgear.cloud` or a custom domain. No trailing slash.
- The OAuth client(s) that will use this Custom UI in production. A separate test client is set up in step 5.
  Client IDs are not baked into the app.
- The intended production hostname of the Custom UI, and Authgear's hostname. Whether they are same-site decides
  which features work; see [Cross-site limitations](#cross-site-limitations).
- **Project name (required; always ask, never pick one yourself).** It becomes the project directory,
  the `package.json` name and the deploy name (e.g. the Cloudflare Worker name). Also ask whether to create it
  as a new subdirectory or to use the current directory.
- Optional: branding (product name, logo URL, primary colour) and the "back to app" URL.

### 2. Analyze the YAML and agree on a screen plan

Read `references/flow-config.md` and do the following:

1. Parse the YAML and check it against the schema rules listed there. Report
   anything that Authgear would reject.
2. Choose the **entry flows**: which `type` + `name` the UI creates for login,
   for signup (or a combined `signup_login`), for forgot-password, and for reauth if the app reauthenticates. If a type
   has several flows, ask which one each entry point uses. If the client has a
   flow allowlist, check that the chosen flows are in it.
3. Walk each entry flow's step tree, following `signup_login` →
   `signup_flow`/`login_flow` references and nested `steps`. List every
   **screen** the user can see and the input each screen submits. Get each screen's response and input shape
   from the upstream sources listed in `references/authflow-api.md`.
4. Run the **review checklist** in `references/flow-config.md`. It covers missing
   `check_account_status` / `change_password` gates, `select_account`
   requirements, passkey and same-site caveats, OAuth callback needs, and
   `link`-form OTP. Also check the [Cross-site limitations](#cross-site-limitations) against the planned hosting.
5. Present the plan to the user: the routes, the screens in each flow, and the
   warnings. Use a compact table or tree. Get confirmation before writing code.
   Ask the user about each security-gate warning; don't silently "fix" their YAML.

### 3. Scaffold the project

Follow the framework reference, e.g. `references/frameworks/react-spa.md`. It tells
you which official docs to read first and what the scaffold must include. Use
the package manager the user prefers; default to npm.

### 4. Implement the flows

Read `references/ui-implementation.md` (the rules every Custom UI must follow) and
`references/authflow-api.md`. For each screen in the plan, fetch the upstream spec section
and input schema file that `authflow-api.md` points to, and apply its errata. Then build:

1. **API client.** `create`, `input`, `batch input`, `get state`, and a typed error class.
   Every call uses `credentials: "include"`. Every create sends the authorization query as `url_query` in the request body
   (for `account_recovery`, with `x_ref` removed; see `ui-implementation.md` §3).
2. **Flow runner.** Keeps the current `state_token` and the result in navigation
   state, so the browser Back button works. Submits input. Navigates to
   `finish_redirect_uri`. Account recovery has none (created without `x_ref`), so it shows a success screen (`ui-implementation.md` §3).
3. **One component per screen in the plan.** Each component dispatches on
   `action.type` plus `data.type` / `identification` / `authentication`. Include
   a fallback "unsupported step" screen that logs the full action, so a YAML
   change that you haven't built yet fails visibly instead of hanging.
4. **Entry routes** for each entry flow (e.g. `/login`, `/signup`, `/forgot-password`),
   **plus** `/oauth-callback` if OAuth is reachable, **plus** a reset-password link route (e.g.
   `/reset-password?code=…`) if account recovery uses `otp_form: link` and the user wants the link to open
   the Custom UI. That also needs an email template change; see `ui-implementation.md` §6. Keep the authorization query
   intact when moving between entry routes.
5. **Error mapping.** Follow `references/error-handling.md`.
6. **Branding and accessibility.** Use labelled inputs, the correct
   `autocomplete` attribute on each field (`username`, `current-password`,
   `new-password`, `one-time-code`, `webauthn`), and visible focus states.
   Make the layout work on mobile.

### 5. Verify locally

1. Type-check and build. Fix every error.
2. Start the dev server. Ask the user to set up a **test client** in the Authgear Portal: a
   **Single Page Application** or **Native App** client, with its **Custom UI URI** (`x_custom_ui_uri`) set to the
   local entry URL (e.g. `http://localhost:5173/login`) and a redirect URI registered (any URL they control, since the code
   doesn't need to be exchanged). Ask them for its client ID. (The built-in `tester` client can't be used,
   because it never redirects to a Custom UI.) Then open a test authorize URL with that client ID:
   `{endpoint}/oauth2/authorize?client_id={client_id}&redirect_uri={a registered redirect URI}&response_type=code&scope=openid+offline_access&code_challenge={challenge}&code_challenge_method=S256`.
   Generate the PKCE pair yourself: a random `code_verifier` (43–128 chars), and `code_challenge` =
   base64url(SHA-256(verifier)) without padding. Keep the verifier if you want to exchange the code afterwards.
   Public clients (SPA / native) are rejected without `code_challenge`.
   Opening `/login` directly, without the authorization query, cannot finish a flow.
3. If browser automation is available (e.g. the `agent-browser` skill or Chrome DevTools MCP),
   walk through at least the first screen of each entry flow. Check that there are
   no CORS errors and that the options render. Ask the user to complete flows that need
   real inboxes, phones or OAuth accounts.

### 6. Record what was built (required)

Write a `.authgear/` folder at the project root. A later update run
depends on it. It is a hidden folder, so make sure no ignore rule excludes it
(`.gitignore`, deploy ignore files), and tell the user to commit it:

- `.authgear/authflow.yaml`: the exact YAML that this build implements, verbatim.
- `.authgear/manifest.json`:
  ```json
  {
    "skill": "authgear-build-custom-ui",
    "projectName": "<the name the user gave in step 1d>",
    "framework": "react-spa",
    "deployTarget": "cloudflare",
    "authgearEndpoint": "https://myproject.authgear.cloud",
    "entryFlows": {
      "login": { "type": "login", "name": "default", "route": "/login" },
      "signup": { "type": "signup_login", "name": "default", "route": "/signup" },
      "forgotPassword": { "type": "account_recovery", "name": "default", "route": "/forgot-password" }
    },
    "deploy": { "name": "<worker/project name>", "url": "<deployed URL, after step 7>" },
    "builtAt": "<ISO date>"
  }
  ```
- `.authgear/flow-map.md`: for each flow, the step tree from the YAML
  (each step's JSON pointer, e.g. `/login_flows/0/steps/0/one_of/1/steps/0`), the
  screen it produces, and the source file(s) that implement it. Also list the
  accepted warnings from step 2 and the reason each was accepted.

### 7. Deploy

Follow the deploy reference (e.g. `references/deploy/cloudflare.md`). Before running any
command that publishes, confirm with the user: it creates public infrastructure on their account.
After deploying:
- Give the deployed URL.
- Tell the user to set the **Custom UI URI** of the production client(s) to the deployed entry URL.
  The test client from step 5 can keep the localhost URL.
- Repeat the smoke test from step 5 against the deployed URL.

### 8. Hand-off checklist

Finish with a short checklist of the Portal / provider settings that this build
depends on. Include only the items that apply:
- **Custom UI enabled on the plan** (`custom_ui_enabled`); otherwise the Custom UI URI can't be saved.
- **Custom UI URI.** `x_custom_ui_uri` on the OAuth client. Authgear redirects sign-ins to it, and its origin is
  allowed for CORS. (CORS also allows a few other origins, e.g. every client's `redirect_uris`; see `cors_matcher.go`.)
- **Authorized redirect URIs** for the user's app. The Custom UI doesn't need one for itself.
- **Flow allowlist entries**, if the client uses `x_authentication_flow_allowlist`. This also applies to flows named
  `default`. They're allowed only if listed, or if the allowlist has a group named `default` that isn't defined in
  `ui.authentication_flow.groups` (`CanCreateFlow` in `pkg/lib/authenticationflow/allowlist.go`).
- **OAuth providers.** Add `{custom-ui-origin}/oauth-callback` to each provider's own
  console as an authorized redirect URI. This is not Authgear's `/sso/oauth2/callback/...` URL.
- **Bot protection site key**, if the YAML enables `bot_protection`. Add the Custom UI's hostnames (and `localhost`) to
  the key's allowed hostnames at Cloudflare Turnstile / Google reCAPTCHA.
- **Hosting domain.** See [Cross-site limitations](#cross-site-limitations).
- **Email templates**, if a recovery link should open the Custom UI (`ui-implementation.md` §6). This is project-wide:
  it affects every client, including Admin-API-triggered resets, and must be done for every locale. See the `authflow-api.md` errata.
- **`x_native_apps`**, if passkeys are used inside a native app's WebView. This is in addition to the domain rule
  (`authflow-api.md` → passkey erratum).

## Cross-site limitations

If the Custom UI is **cross-site** with Authgear (a different registrable domain, e.g. `*.workers.dev` vs
`*.authgear.cloud`), sign-in still works, but these features don't:

| Feature | Why |
|---------|-----|
| `select_account` ("Continue as …") | The Authgear session cookie isn't sent cross-site, so the option never appears |
| Passkeys (`passkey`, `primary_passkey`, `prompt_create_passkey`) | The browser rejects Authgear's `rpId` from another site (see the passkey erratum; this is even stricter than same-site) |
| SSO across apps (Authgear session) | The session cookie set at the end of the flow may be dropped as a third-party cookie |
| "Remember this device" (`device_token`) | Same reason: the device-token cookie may be dropped |

In step 2, if the planned hosting is cross-site and the YAML uses any of these, warn the user. Offer a same-site
custom domain, or ask them to accept the limitation (record it in `flow-map.md`).

## Reauthentication

When the user's app asks a signed-in user to confirm their identity again (e.g. the SDK's `reauthenticate`), Authgear
redirects to the same Custom UI URI. It forwards `id_token_hint` (but not `prompt`).

- Detect `id_token_hint` in the authorization query, and create a **`reauth`** flow (from `reauth_flows`, or `default`)
  instead of `login`, still sending `url_query` in the body. Confirm with the user that their app only sends
  `id_token_hint` for reauthentication.
- The flow must start with an `identify` step using `identification: id_token`, as the built-in one does
  (`generate_config_reauth_flow.go`). That step completes by itself from the session's `id_token_hint`, so the user
  normally sees only the `authenticate` screens (password, OTP, TOTP, passkey…). Don't show an identifier field.
  A custom reauth flow without that step has no user to authenticate; flag it as an error.
- `reauth_flows` allow only `identify` (`id_token`) and `authenticate` steps (no `recovery_code` / `device_token`).
  Run the review checklist's **Errors** and **Notes** on them, but **not** its Security items:
  `check_account_status`, `change_password` and `terminate_other_sessions` aren't allowed in a reauth flow, so suggesting
  them would produce YAML that Authgear rejects.
- Record it as an entry flow in `manifest.json` (e.g. `"reauth": { "type": "reauth", "name": "default", "route": "/login" }`).
- Sources: `docs/specs/authentication-flow.md` (type: reauth),
  `pkg/lib/authenticationflow/declarative/intent_reauth_flow_step_identify.go`, and `generate_config_reauth_flow.go`.

## Updating an existing Custom UI

When the user provides a new YAML (or asks to "update the custom UI"):

1. Read `.authgear/manifest.json`, `authflow.yaml` and `flow-map.md`.
   Then read the project's current source, because the user may have edited it.
2. Diff the new YAML against `.authgear/authflow.yaml` **semantically**.
   Compare by flow `type`+`name` and step position or `name`, not by text lines. Classify each change:
   - **Added screens**: a new step type, identification, authentication, or nested branch.
   - **Removed screens**: delete the component and its route/dispatch case, unless it is still reachable from another flow.
   - **Changed parameters**: e.g. `target_step`, `optional`, `bot_protection`,
     `allowed_channels`, form fields, or flow renames. Usually these only change config or dispatch.
   - **Entry-flow changes**: a new or renamed flow, or a change of `signup` ↔ `signup_login`.
3. Re-run the review checklist (step 2.4) on the new YAML. Show the user the change
   plan: files to add, change, and delete, plus new warnings. Get confirmation.
4. Apply the changes. Keep the user's custom edits (styling, copy) unless they conflict.
5. Verify (step 5). Then overwrite `authflow.yaml`, update `manifest.json`
   (`builtAt`, `entryFlows`) and `flow-map.md`.
6. Ask whether to redeploy. If yes, follow step 7.

When the framework or deploy target changes, treat it as a new project. Reuse the
screen plan and the copy, not the code.

## References

| File | Read when |
|------|-----------|
| `references/flow-config.md` | Step 2 and every update. Links to the config schema and specs, the analysis procedure, and the review checklist. |
| `references/authflow-api.md` | Step 4. Source map (which upstream file answers which question) and verified errata. |
| `references/ui-implementation.md` | Step 4. Rules for browser-side Custom UIs: url_query, CORS, state tokens, OAuth round trip, finish, OTP cooldown, passkeys, bot protection. |
| `references/error-handling.md` | Step 4. Links to the error sources, mapping rules, and gotchas (InvariantViolated causes, lockout vs rate limit). |
| `references/frameworks/react-spa.md` | Step 3 when the framework is React (SPA). Links to the official docs and the scaffold requirements. |
| `references/deploy/cloudflare.md` | Step 7 when the target is Cloudflare. Links to the official docs and the deploy requirements. |

To add a framework or deploy target later, add a file under `references/frameworks/`
or `references/deploy/` with the same structure, and add the option to the
AskUserQuestion in step 1.
