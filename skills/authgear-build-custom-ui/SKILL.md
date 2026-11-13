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
- **Ask questions with AskUserQuestion, never as a numbered list in prose.** Whenever an answer can be offered as choices
  (yes/no, confirming a value read from the config, picking from a list), use AskUserQuestion. Batch up to 4 related
  questions per call, 2–4 options each, the recommended option first. "Other" is added automatically, so the user can
  always type something else. Put the context (what you found in the config, why it matters) in the question text and
  option descriptions, so each question stands on its own. Read values from the config instead of asking whenever you can,
  and offer them as the recommended option to confirm. Only answers that can't have options (e.g. the project name)
  are asked in plain text, one short question per message, after the structured questions.
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
- **Never ask the user to edit raw config keys.** Most users don't know how to, and it's easy to break the project.
  Read the config to learn things, but when a setting must change, tell the user **where in the Portal** to change it,
  using the Portal's labels:
  - Custom UI URI (`x_custom_ui_uri`): **Applications → (the client) → Custom UI → Custom UI URI**. If that section is
    missing, Custom UI isn't on their plan; they contact Authgear support.
  - Native apps for passkeys in WebViews (`x_native_apps`): **Applications → (the native app client) → Passkeys & passwords
    in mobile apps → Add iOS app / Add Android app**. It only takes effect on a custom domain.
  - Settings with **no Portal UI**, such as the flow allowlist (`x_authentication_flow_allowlist`) and flow groups: don't
    mention them to the user and don't ask them to change them. Work within them (e.g. only offer flows the client is
    allowed to create).
  - The one exception is the flow definitions themselves (step 1a): there is no Portal UI for them, so a missing flow can
    only be added in Advanced → Edit Config. Give the user the exact YAML and where to paste it, and offer to walk them
    through it.

  Keep the raw key names out of what you say to the user; they're for you, to read the config and the source.
- **Commit step by step, in the generated project.** Don't leave all the work unstaged for one commit at the end. Commit
  each completed, working unit as you go, so the user can review, bisect and revert:
  - New project: if the project isn't inside a git repository, run `git init` when scaffolding (step 3). If it's inside the
    user's existing repository and there are uncommitted changes there, ask before committing anything.
  - Commit points: the scaffold (step 3); the API client and flow runner; each entry flow or group of related screens
    (step 4); fixes from verification (step 5); `.authgear/` (step 6); deploy config (step 7). In an update run, commit
    each change in the agreed change plan, then the updated `.authgear/`.
  - Each commit builds and type-checks. Stage only the files of that step (no `git add -A` that sweeps in unrelated files),
    never commit `.env.local` or other secrets, and write a message saying what the step did.
  - Commit to the current branch. Never push, and never rewrite history (amend, rebase, force) unless the user asks.
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

**a. The config (required).** Ask for their **whole `authgear.yaml`**, as a file path or pasted, and tell them where to
find it:
- **Authgear Portal:** open the project, then **Advanced → Edit Config** (`/project/<project id>/edit-config`). The editor
  shows the full `authgear.yaml`. Copy it **without editing anything**; the page warns about direct edits, and saving there
  isn't needed.
- **Self-hosted:** the `authgear.yaml` in their deployment's config source.

The whole file is best: it holds `authentication_flow` and every related section below in one go, and it contains **no
secrets** (those live in `authgear.secrets.yaml`, which you must never ask for). If the user prefers to share only parts,
accept the bare `authentication_flow` section (`login_flows:` …) and ask for the related sections below separately, or ask
the questions directly. Ask with AskUserQuestion (see the rule at the top); don't send the user a long list of config keys.

**Only flows defined in the config are supported.** Every flow the UI uses must be written out in `authentication_flow`:
the entry flows, plus every flow they reference (a `signup_login` branch's `signup_flow` / `login_flow`, an
`account_linking` override's `login_flow`). A flow that isn't defined is generated by the server at runtime (a generated
`default`, from `generate_config_*.go`), and its steps change whenever unrelated settings change (login methods, 2FA,
verification, bot protection, …). A static UI built against it would silently break, so **never build against a generated
flow**. A flow that is defined and happens to be named `default` is fine: it's in the config.

If an entry point the user needs has no defined flow (or a referenced flow is missing), stop and explain why. Offer to draft
the definition: derive what the server generates today from `generate_config_*.go` and their config, and show it as YAML for
them to add to `authentication_flow` (Portal: Advanced → Edit Config, or their config source). Continue once they've
added it and shared the updated config.

**Choosing the flows.** Once you have the config, list the flows it defines per type (`login_flows`, `signup_flows`,
`signup_login_flows`, `account_recovery_flows`, `reauth_flows`). Then ask the user which flow each entry point uses (login,
signup or signup-login, forgot password, reauth if needed). Use AskUserQuestion with the flow names as options when they
fit; if a type has exactly one defined flow, use it and say so.
Also read `ui.authentication_flow.groups` and the `x_authentication_flow_allowlist` of the client(s) that will use the
Custom UI (ask which clients first, from `oauth.clients`): if a client has an allowlist, only offer the flows it allows,
without mentioning the allowlist (it has no Portal UI). The Custom UI picks the flow by name when it creates it, so this choice is
the user's.

Some runtime behaviour is set **outside** `authentication_flow`. Read these from the config (or ask, if the user only
shared part of it):
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

Also ask whether their app uses **reauthentication** (asking a signed-in user to confirm their identity again,
e.g. the SDK's `reauthenticate`). If it does, the Custom UI must also handle the `reauth` flow; see
[Reauthentication](#reauthentication).

**b. Framework and deployment target.** **Always ask these with AskUserQuestion, even though each has only one dedicated
reference today.** Don't decide for the user or announce "those are the only options": the user must get the chance to pick
"Other" and type what they want. Ask both in one call (AskUserQuestion needs at least two options per question, so each has
a real second choice; "Other" is added automatically):

```json
{
  "questions": [
    {
      "question": "Which framework should the Custom UI use?",
      "header": "Framework",
      "multiSelect": false,
      "options": [
        { "label": "React SPA (Recommended)", "description": "Client-side React app built with Vite and TypeScript. No server; static files call the Authentication Flow API from the browser. Not Next.js." },
        { "label": "Explain the options", "description": "Tell me what this skill supports and why, then ask again." }
      ]
    },
    {
      "question": "Where should the Custom UI be deployed?",
      "header": "Deploy",
      "multiSelect": false,
      "options": [
        { "label": "Cloudflare (Recommended)", "description": "Deploy as static assets on Cloudflare Workers with wrangler. You log in to Cloudflare yourself." },
        { "label": "Build only", "description": "Build and test locally; I'll deploy the static files myself." }
      ]
    }
  ]
}
```

Handling the answers:
- **"Explain the options"**: explain that React SPA is the recommended path with its own reference here (the Custom UI is
  static files calling the API from the browser, so no server framework is needed), and that any other framework can be
  typed under "Other". Then ask the framework question again.
- **"Other" framework** (e.g. Vue, Svelte, Next.js): use it. Search the web for its current official docs (getting started,
  routing, env variables, static/SPA build) and use `references/frameworks/react-spa.md` as the checklist of what must be
  true, mapping each requirement and gotcha to the chosen framework (e.g. the double-run guard for flow creation and the
  OAuth callback, reading the query only in entry routes, full-page navigation for `finish_redirect_uri`). Keep the
  Authentication Flow API calls in the browser, as every reference here assumes. If the framework renders on a server,
  tell the user what that changes (e.g. the host must run it, not just serve files). Show the user the mapping before scaffolding.
- **"Other" deploy target** (e.g. Vercel, Netlify): use it. Search the web for that platform's current official docs and
  meet the same requirements as `references/deploy/cloudflare.md` (SPA fallback, build-time env, the user logs in
  themselves, confirm before publishing, security headers, domain choice incl. Apple's `form_post` callback, post-deploy
  steps, recording in the manifest). Show the user how each requirement will be met on that platform before deploying.
- **"Build only"**: skip step 7's commands, and instead list what any host must provide: SPA fallback to `index.html`, the
  security headers (CSP, `Referrer-Policy`, `frame-ancestors`), and Apple's `form_post` callback if Apple is used. Take
  these from `references/deploy/cloudflare.md`; they aren't Cloudflare-specific.
- Record the choices in the manifest (`framework`, e.g. `"react-spa"` or `"vue-spa"`; `deployTarget`, e.g. `"cloudflare"`,
  `"vercel"` or `"none"`).

The same applies to "Other" in the UI stack question below: research that library's current docs and use it.

The reference for each framework is in `references/frameworks/`: React SPA → `references/frameworks/react-spa.md`.

Then ask about the UI stack in a second AskUserQuestion call (one call, two questions). **Always ask; never skip it because
defaults exist.** The defaults go first; the user can name anything else through "Other":

```json
{
  "questions": [
    {
      "question": "Which styling approach should the Custom UI use?",
      "header": "Styling",
      "multiSelect": false,
      "options": [
        { "label": "Tailwind CSS (Recommended)", "description": "Utility-first CSS, installed through its Vite plugin." },
        { "label": "CSS Modules", "description": "Plain scoped CSS files. No extra dependency; Vite supports it out of the box." }
      ]
    },
    {
      "question": "Which component library should the Custom UI use?",
      "header": "Components",
      "multiSelect": false,
      "options": [
        { "label": "Radix UI (Recommended)", "description": "Radix Primitives: unstyled, accessible components (dialog, select, checkbox, …), styled with the chosen styling approach." },
        { "label": "None", "description": "Hand-written components only. Fewest dependencies." }
      ]
    }
  ]
}
```

If the user names another library, follow its current official docs the same way, and check that it works in a
client-only Vite SPA (no SSR-only setup). Record both answers in the manifest (step 6). The framework reference says how to
set up the defaults.

**c. Deploy reference.** Cloudflare → `references/deploy/cloudflare.md`; any other target → that file as the checklist,
plus the platform's own docs (see above). To give a target first-class support (e.g. Vercel), add it as an option in the
step 1b question and a file under `references/deploy/`.

**d. Project details.** Take as much as possible from the config; ask only what it can't answer:
- **Authgear endpoint:** use `http.public_origin` from the config, without asking. Only if the user didn't share it, ask
  them for the **Endpoint** shown on their application's page in the Portal. No trailing slash.
- **Client:** find the clients in `oauth.clients` (`name`, `client_id`).
  - None: ask the user to create one in the Portal (Applications) for the app that will use this Custom UI, and to share
    the updated config or its client ID.
  - Exactly one: use it; just mention which.
  - More than one: ask which one(s) will use the Custom UI (AskUserQuestion, options = client names + IDs,
    `multiSelect: true`).

  Read the chosen clients' `x_authentication_flow_allowlist` from the config instead of asking. Client IDs are not baked
  into the app. A test client for localhost is set up in step 5.
- **OAuth providers:** read `identity.oauth.providers`; don't ask about them.
  - Providers listed: use them (alias, type, `credentials_behavior`), and apply the Apple and demo-credential notes in
    `references/flow-config.md`.
  - None listed, and no chosen flow reaches `identification: oauth`: there's no social login; say nothing.
  - None listed, but a chosen flow reaches `oauth`: tell the user their flow has an OAuth option but no provider is set up,
    and ask whether they want social login in the UI (AskUserQuestion: "No, leave it out (Recommended)" / "Yes"). On "Yes",
    ask them to add the provider(s) in the Portal (Authentication → Social / Enterprise Login) and share the updated config.
    Until then, the UI doesn't render an OAuth button for a provider that doesn't exist.
- **Hosting domain:** don't ask now. Nobody knows the deployed host before deploying: test on `localhost` (step 5) and
  choose the domain in step 7. In step 2, just warn about the [Cross-site limitations](#cross-site-limitations) that
  apply to *this* config, if the UI ends up on a domain outside Authgear's site.
- **Project location:** look at the current directory first. If it is empty, or looks like a fresh repo (e.g. only
  `.git`, `README`, `LICENSE`, `.gitignore`, no `package.json` or source), recommend **"Current directory"**. Otherwise
  recommend **"New subdirectory"**. Ask with AskUserQuestion, the recommended option first, and say what you saw in the
  description.
- **Project name (required; always ask, never pick one yourself):** plain text, on its own. It becomes the project
  directory (if a subdirectory), the `package.json` name and the deploy name (e.g. the Cloudflare Worker name).

Don't ask about branding (product name, logo, colours). Build a clean, neutral UI; the user restyles it afterwards.

### 2. Analyze the YAML and agree on a screen plan

Read `references/flow-config.md` and do the following:

1. Parse the YAML and check it against the schema rules listed there. Report
   anything that Authgear would reject.
2. Use the **entry flows** the user chose in step 1a (the `type` + `name` the UI creates for login, for signup or a
   combined `signup_login`, for forgot-password, and for reauth if the app reauthenticates). All of them, and every flow
   they reference, must be defined in the YAML (step 1a). If the client has a flow allowlist, check that the chosen flows are in it.
3. Walk each entry flow's step tree, following `signup_login` →
   `signup_flow`/`login_flow` references and nested `steps`. List every
   **screen** the user can see and the input each screen submits. Get each screen's response and input shape
   from the upstream sources listed in `references/authflow-api.md`.
4. Run the **review checklist** in `references/flow-config.md`. It covers missing
   `check_account_status` / `change_password` gates, `select_account`
   requirements, passkey and same-site caveats, OAuth callback needs, and
   `link`-form OTP. Also check the [Cross-site limitations](#cross-site-limitations) that apply to this config (the domain is chosen in step 7).
5. Present the plan to the user: the routes, the screens in each flow, and the
   warnings. Use a compact table or tree. Get confirmation before writing code.
   Ask the user about each security-gate warning; don't silently "fix" their YAML.

### 3. Scaffold the project

Follow the framework reference, e.g. `references/frameworks/react-spa.md` (for another framework, the mapping agreed in step 1b). It tells
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
6. **Accessibility.** Keep the look clean and neutral (no branding). Use labelled inputs, the correct
   `autocomplete` attribute on each field (`username`, `current-password`,
   `new-password`, `one-time-code`, `webauthn`), and visible focus states.
   Make the layout work on mobile.

### 5. Verify locally

1. Type-check and build. Fix every error.
2. Start the dev server. Ask the user to set up a **test client** in the Authgear Portal: a
   **Single Page Application** or **Native App** client, with its **Custom UI URI** (Applications → the client → Custom UI) set to the
   local entry URL (e.g. `http://localhost:5173/login`) and a redirect URI registered (any URL they control, since the code
   doesn't need to be exchanged). Ask them for its client ID. **If they can't find the Custom UI URI setting**, or saving
   it fails with "custom ui is disallowed", Custom UI isn't enabled for their project (it's a plan feature,
   `oauth.client.custom_ui_enabled` in `pkg/lib/config/feature_oauth.go`): ask them to contact Authgear support to enable it. (The built-in `tester` client can't be used,
   because it never redirects to a Custom UI.) Then open a test authorize URL with that client ID:
   `{endpoint}/oauth2/authorize?client_id={client_id}&redirect_uri={a registered redirect URI}&response_type=code&scope=openid+offline_access&code_challenge={challenge}&code_challenge_method=S256`.
   Generate the PKCE pair yourself: a random `code_verifier` (43–128 chars), and `code_challenge` =
   base64url(SHA-256(verifier)) without padding. Keep the verifier if you want to exchange the code afterwards.
   Public clients (SPA / native) are rejected without `code_challenge`.
   Opening `/login` directly, without the authorization query, cannot finish a flow.
3. **Browser test (if a browser tool is available, and with the user's consent).** Check which tools you have, e.g.
   Chrome DevTools MCP (`navigate_page`, `take_snapshot`, `fill`, `click`, `list_console_messages`,
   `list_network_requests`, `take_screenshot`) or the `agent-browser` skill. If there's one, ask first (AskUserQuestion):
   "Run browser tests (Recommended)" / "Skip, I'll test manually". In the question, say what it involves: the agent drives
   a browser against their Authgear project, and testing signup **creates real users** in it. Prefer an isolated browser
   profile if the tool supports one.

   With consent, drive the real flows from the test authorize URL above:
   - **Each entry flow**, as far as you can go: the first screen renders the options from the config; moving between
     entry routes keeps the authorization query; Back and reload resume the flow instead of restarting it.
   - **Errors:** e.g. a wrong password or an invalid code shows the mapped message, not raw server text.
   - **Finish:** the browser ends at the test client's redirect URI with a `code` (and the `state` you sent).
   - **Every step:** no console errors, no CORS failures, and no unexpected 4xx/5xx in the network log (read the error
     `reason` when there is one).
   - A screenshot at mobile width of the main screens, to check the layout.

   Credentials and secrets: ask the user for a **test** account (or a test email/phone for signup); never use their real
   account. Don't write credentials, OTP codes or the PKCE verifier into files or commits. When a step needs something only
   the user has (an OTP from their inbox or phone, an OAuth provider login, a passkey prompt, a CAPTCHA), pause and ask
   them to give you the code or complete that step in the browser, then continue.

   Fix what the test finds and commit the fixes (see "Commit step by step"). Without a browser tool, or if the user
   declines, give them a short manual checklist covering the same points.

### 6. Record what was built (required)

Write a `.authgear/` folder at the project root. A later update run
depends on it. It is a hidden folder, so make sure no ignore rule excludes it
(`.gitignore`, deploy ignore files), and commit it (see "Commit step by step"):

- `.authgear/authflow.yaml`: the exact YAML that this build implements, verbatim.
- `.authgear/manifest.json`:
  ```json
  {
    "skill": "authgear-build-custom-ui",
    "projectName": "<the name the user gave in step 1d>",
    "framework": "react-spa",
    "ui": { "styling": "tailwindcss", "components": "radix-ui" },
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

If the user chose **Build only** (step 1b), don't deploy. Give the host requirements listed there, and tell them to set
the production Custom UI URI once they've deployed.

Otherwise, follow the deploy reference (`references/deploy/cloudflare.md`, or for another platform the mapping agreed in
step 1b). Before running any
command that publishes, confirm with the user: it creates public infrastructure on their account.
After deploying:
- Give the deployed URL.
- Tell the user to set the **Custom UI URI** of the production client(s) to the deployed entry URL.
  The test client from step 5 can keep the localhost URL.
- Repeat the step 5 test against the deployed URL (browser test with the same consent, if the user agreed), after they update the Custom UI URI.

### 8. Hand-off checklist

Finish with a short checklist of the Portal / provider settings that this build
depends on. Include only the items that apply:
- **Custom UI enabled on the plan** (`custom_ui_enabled`): if the Custom UI URI setting is missing in the Portal, or
  saving it fails with "custom ui is disallowed", contact Authgear support.
- **Custom UI URI.** Portal: Applications → the client → Custom UI → Custom UI URI. Authgear redirects sign-ins to it,
  and allows its origin for CORS.
- **Authorized redirect URIs** for the user's app. The Custom UI doesn't need one for itself.
- **OAuth providers.** Add `{custom-ui-origin}/oauth-callback` to each provider's own
  console as an authorized redirect URI. This is not Authgear's `/sso/oauth2/callback/...` URL.
- **Bot protection site key**, if the YAML enables `bot_protection`. Add the Custom UI's hostnames (and `localhost`) to
  the key's allowed hostnames at Cloudflare Turnstile / Google reCAPTCHA.
- **Hosting domain.** See [Cross-site limitations](#cross-site-limitations).
- **Email templates**, if a recovery link should open the Custom UI (`ui-implementation.md` §6). This is project-wide:
  it affects every client, including Admin-API-triggered resets, and must be done for every locale. See the `authflow-api.md` errata.
- **Mobile apps**, if passkeys are used inside a native app's WebView. Portal: Applications → the native app client →
  Passkeys & passwords in mobile apps → Add iOS app / Add Android app (needs a custom domain). This is in addition to the
  domain rule (`authflow-api.md` → passkey erratum).

## Cross-site limitations

If the Custom UI is **cross-site** with Authgear (a different registrable domain, e.g. `*.workers.dev` vs
`*.authgear.cloud`), sign-in still works, but these features don't:

| Feature | Why |
|---------|-----|
| `select_account` ("Continue as …") | The Authgear session cookie isn't sent cross-site, so the option never appears |
| Passkeys (`passkey`, `primary_passkey`, `prompt_create_passkey`) | The browser rejects Authgear's `rpId` from another site (see the passkey erratum; this is even stricter than same-site) |
| SSO across apps (Authgear session) | The session cookie set at the end of the flow may be dropped as a third-party cookie |
| "Remember this device" (`device_token`) | Same reason: the device-token cookie may be dropped |

In step 2, if the YAML uses any of these, warn the user that they only work when the UI is hosted on a domain within
Authgear's site (a custom domain), not on a platform default such as `*.workers.dev`. The domain itself is chosen in step 7:
offer a same-site custom domain there, or ask them to accept the limitation (record it in `flow-map.md`).

## Reauthentication

When the user's app asks a signed-in user to confirm their identity again (e.g. the SDK's `reauthenticate`), Authgear
redirects to the same Custom UI URI. It forwards `id_token_hint` (but not `prompt`).

- Detect `id_token_hint` in the authorization query, and create a **`reauth`** flow (one defined in `reauth_flows`; a
  generated one isn't supported, see step 1a) instead of `login`, still sending `url_query` in the body. Confirm with the user that their app only sends
  `id_token_hint` for reauthentication.
- The flow must start with an `identify` step using `identification: id_token`, as the generated one does
  (`generate_config_reauth_flow.go`; use it as the model when drafting a definition). That step completes by itself from the session's `id_token_hint`, so the user
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
   Don't ask the framework or UI-stack questions again. Build new screens with the styling and component library in
   `manifest.ui` (older manifests without `ui`: infer them from `package.json` and the existing code).
2. Diff the new YAML against `.authgear/authflow.yaml` **semantically**.
   Compare by flow `type`+`name` and step position or `name`, not by text lines. Classify each change:
   - **Added screens**: a new step type, identification, authentication, or nested branch.
   - **Removed screens**: delete the component and its route/dispatch case, unless it is still reachable from another flow.
   - **Changed parameters**: e.g. `target_step`, `optional`, `bot_protection`,
     `allowed_channels`, form fields, or flow renames. Usually these only change config or dispatch.
   - **Entry-flow changes**: a new or renamed flow, or a change of `signup` ↔ `signup_login`. If the new YAML no longer defines a flow the UI uses (removed, or left to be generated), stop and handle it as in step 1a.
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
