# Authentication Flow config (YAML): how to analyze it

## Read the sources first

Base: `https://raw.githubusercontent.com/authgear/authgear-server/main/`

| Need | Read |
|------|------|
| **JSON schema** (allowed step types per flow type, `identification`/`authentication` enums, required keys such as `target_step`, `signup_login` rules). This is the source of truth for validation. | `pkg/lib/config/authentication_flow.go` |
| Concepts, nesting semantics, many example configs | `docs/specs/authentication-flow.md` |
| Valid and invalid config test cases (useful to confirm an edge case) | `pkg/lib/config/testdata/*flow*_tests.yaml` |
| What Authgear's built-in `default` flows look like (the reference layout for security gates) | `pkg/lib/authenticationflow/declarative/generate_config_login_flow.go` (and `generate_config_signup_flow.go`, etc.) |
| Flow groups and allowlists | `docs/specs/authentication-flow-selection.md` |
| `fill_form` and profile fields | `docs/specs/user-profile/profile-filling.md` |
| `select_account` config rules | `docs/specs/custom-ui-select-account.md` |
| Bot protection config | `pkg/lib/config/authentication_flow_bot_protection.go`, `pkg/lib/config/bot_protection.go` |

Read nested `steps` like this: a branch's `steps` run immediately after the step that chose that branch,
before the parent's next sibling step. `target_step` refers to another step by its `name`.

## Procedure

1. **Validate.** Check the YAML against the schema file. Report anything Authgear would reject.
2. **Choose the entry flows**: login / signup (or `signup_login`) / forgot-password, by `type` + `name`.
   If a type has several flows, ask which one each entry uses.
3. **Walk each entry flow's tree.** Follow nested `steps`, and `signup_login` → `signup_flow`/`login_flow`.
   For each reachable step / identification / authentication, note the screen it needs. Look up the
   response and input shape for each in `authflow-api.md` → source map.
4. **Run the review checklist** below.
5. **Present the screen plan** to the user and get confirmation. Example:

```
/login  → login "default"
  identify: [email → authenticate(primary_password → [change_password]) | oauth | select_account]
  check_account_status (gate, no screen)
/signup → signup_login "default"
  identify: [email → signup "default" | login "default"]
    signup: identify(email) → verify(OTP) → create_authenticator(primary_password)
/forgot-password → account_recovery "default"
  identify(email) → select_destination(auto if 1) → verify_account_recovery_code → reset_password
/oauth-callback
Warnings: …
```

Choosing entry routes: Authgear sends every user to the **one** Custom UI URI, and passes no
"page" hint. Make that URI the login route. Link to the other entry routes, keeping the query string.
`reauth` is needed only if the user's app reauthenticates (SKILL.md → Reauthentication). It uses the same
Custom UI URI and is chosen by `id_token_hint`. `promote` is needed only if the user asks for it.

## Review checklist (run on every new or changed YAML)

Classify each finding as **Error**, **Security** or **Note**. Never edit the user's YAML silently.
Show them the fix.

**Errors**
- [ ] A step type, identification or authentication that the schema doesn't allow for that flow type.
- [ ] `verify` without `target_step`, or `change_password` without one. A `target_step` that names a step which doesn't exist, or a step of the wrong kind:
      `change_password` must point at an `authenticate` step and `verify` at an `identify` step.
      A bare `- type: change_password` is a common mistake; the schema rejects it.
- [ ] A `signup_login` branch missing `signup_flow`/`login_flow`, or a `select_account` branch that has `signup_flow`.
      A reference to a flow that isn't defined (and isn't `default`).
- [ ] A `signup_login` `select_account` branch whose target `login_flow` has no `select_account` option of its own.
- [ ] An entry flow that isn't in the client's `x_authentication_flow_allowlist`, when the client has one.

**Security** (a custom flow runs *only* the steps it declares)
- [ ] A login flow without `check_account_status` after authentication. Without it, **disabled or deactivated users can sign in.**
- [ ] A `primary_password` branch without `change_password` targeting its authenticate step. Without it, forced change, expiry and policy resets are skipped.
- [ ] No `terminate_other_sessions`, when the client limits concurrent sessions. Ask the user.

Compare against the built-in layout in `generate_config_login_flow.go`.

**Notes / caveats**
- [ ] Cross-site hosting combined with `select_account`, passkeys, or `device_token` (or reliance on SSO across apps):
      these won't work. Warn the user (SKILL.md → Cross-site limitations).
- [ ] `passkey`, `primary_passkey` and `prompt_create_passkey`: in a browser, the UI must be on Authgear's host or a **subdomain of it**,
      which is stricter than same-site. Inside a native app's WebView, `x_native_apps` and a custom domain are needed instead
      (see `authflow-api.md` errata). Confirm the domain plan.
- [ ] `oauth` needs an `/oauth-callback` route, and the provider consoles must list it. Flag app-based providers (WeChat).
- [ ] **Apple** (an `oauth` option with `provider_type: apple`, or the user says they use it): Apple returns via a form POST,
      which static files can't receive (see errata). Tell the user, and **ask them to decide** what to do.
- [ ] `reauth_flows` present, or the app uses reauthentication: the Custom UI must detect `id_token_hint` and run `reauth`
      (SKILL.md → Reauthentication).
- [ ] An OTP with `otp_form: link`: a login/verify link needs a waiting screen, because only Authgear's page can approve it.
      A **recovery** link can open the Custom UI if the user customizes the email template; ask whether they want that.
      Otherwise the reset finishes on Authgear's page. `otp_form: code` keeps everything on the Custom UI.
- [ ] `bot_protection` needs the provider widget and a site key. Ask for the key.
- [ ] `fill_form` / identify `form`: build renderers only for the field types the YAML's pointers produce.
- [ ] Phone identification needs an E.164 input. Ask for the default country.
- [ ] `optional` authenticate steps, and `change_password` / `terminate_other_sessions`, may not appear at runtime. That is expected.
