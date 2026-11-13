# Error handling

## Sources

Base: `https://raw.githubusercontent.com/authgear/authgear-server/main/`

| Need | Read |
|------|------|
| Error envelope | "Error response" in `docs/specs/authentication-flow-api-reference.md` |
| How `info.cause` / `info.causes` are serialized | `pkg/api/apierrors/error.go` |
| Core reasons (`InvalidCredentials`, `InvariantViolated` + causes, `UserNotFound`) | `pkg/api/errors.go`. Search the code for `NewInvariantViolated(` to get the cause kinds. |
| OTP errors | `pkg/lib/authn/otp/errors.go` |
| Password policy violations | `pkg/lib/authn/authenticator/password/errors.go`, `policy.go` |
| Lockout / rate limit | `pkg/lib/lockout/error.go`, `pkg/lib/ratelimit/error.go` |
| Account status errors | `pkg/lib/authn/user/errors.go` |
| Bot protection errors | `pkg/lib/botprotection/errors.go` |
| Authflow errors (`AuthenticationFlowNotFound`, `AuthenticationFlowFlowNotFound`, `SelectAccountSessionChanged`, …) | `pkg/lib/authenticationflow/errors.go`, `pkg/lib/authenticationflow/declarative/error.go` |

To find the source of any `reason`, search the repo for `WithReason("<Reason>")`.

## Rules

- Branch on `error.reason`. Never branch on `message`, and never show `message` to users.
- Use one typed error class with `reason`, `code`, `info`. Log the full error, including `tracking_id`, to the console,
  so bug reports can be diagnosed.
- Map each reason to friendly copy, and keep a generic fallback. Only map the reasons that the screens you built can trigger.
- Errors leave the flow at the same state (the same `state_token` is still valid). Stay on the screen and show the error.
  The exceptions are `AuthenticationFlowNotFound` and `SelectAccountSessionChanged`. For these, recreate the flow from the entry route, keeping `urlQuery`.

## Gotchas (verified against source, Nov 2026)

- `InvariantViolated` is overloaded. Read `info.cause.kind`: `DuplicatedIdentity` (that login ID is already taken),
  `NoAuthenticator`, `MismatchedUser`, `ClaimNotVerifiable`, `IdentityModifyDisabled`, `InvalidLoginIDKey`
  (re-grep `NewInvariantViolated(` for new ones).
- `InvalidOTPCode`: `info.cause.kind` is `CodeNotFound` (expired), `InvalidCode` or `UsedCode`.
  Too many wrong attempts returns `RateLimited` instead, and the screen's `failed_attempt_rate_limit_exceeded` becomes true. Prompt for a resend.
- `PasswordPolicyViolated`: `info.causes[]` lists the failed rules. Each cause is
  `{ "Name": "PasswordTooShort", "Info": { … } }`, with capitalized keys because the Go struct's fields set no JSON names.
  Names: `PasswordTooShort`, `PasswordUppercaseRequired`, `PasswordLowercaseRequired`, `PasswordAlphabetRequired`,
  `PasswordDigitRequired`, `PasswordSymbolRequired`, `PasswordContainingExcludedKeywords`, `PasswordBelowGuessableLevel`,
  `PasswordReused` (`pkg/lib/authn/authenticator/password/policy.go`). Auth UI matches violations exactly this way,
  on `cause["Name"]`: see `NewPasswordPolicyViewModel` in `pkg/auth/handler/webapp/viewmodels/password_policy.go`,
  and `resources/authgear/templates/en/web/authflowv2/__password_policy.html` for the hint list and `Info` keys
  (`min_length`, `min_level`). Mark the matching hints as failed.
- `AccountLockout` carries `info.until` (a timestamp). Show "Try again in m:ss" and disable submit until then.
- `RateLimited` carries **no deadline**. `info` may have `rate_limit: { name, group }` (absent when the bucket has no name),
  and too many OTP attempts gives only `bucket_name: "TrackFailedOTPAttemptBucket"`. Don't rely on any `info` field.
  Show a generic "Too many attempts, please wait". Don't look for `retry_after`-style fields; the server doesn't set them.
- Account status (from `check_account_status`): `DisabledUser` (with optional `info.reason`, which can be shown),
  `AnonymizedUser`, `UserOutsideValidPeriod`, `ScheduledDeletionByAdmin`, `ScheduledDeletionByEndUser`,
  `ScheduledAnonymizationByAdmin` (`pkg/lib/authn/user/errors.go`; `DeactivatedUser` is commented out there and never
  returned). These are terminal. Show an explanation, not a retry.
- `AuthenticationFlowNotAllowed` on create: the flow isn't in the client's `x_authentication_flow_allowlist`. This is a
  configuration problem: in dev builds, show a hint that this client isn't allowed to use this flow. The allowlist has no
  Portal UI, so the fix is to use an allowed flow, not to tell the user to edit it.
- `AuthenticationFlowFlowNotFound` on create (`declarative/error.go`): the flow `name` isn't defined. Usually the manifest's
  entry flow no longer matches the YAML. This is a config problem, so show a developer hint and **don't** retry or recreate.
  It's a different reason from `AuthenticationFlowNotFound` (an expired or bad state token, which *is* recovered by recreating).
- `AuthenticationFlowNoPublicSignup`: public signup is disabled. Say signup isn't available and link to sign-in.
- `ValidationFailed`: the input shape doesn't match the schema. This is a bug in the UI, not a user error. Log `info.causes`. Show a generic message.
- Bot protection: the spec's `BotProtectionRequired` doesn't exist in the source. A missing `bot_protection` input fails
  schema validation (`ValidationFailed`). A bad or expired token gives `BotProtectionVerificationFailed`; reset the widget
  and let the user retry. `BotProtectionVerificationServiceUnavailable` means the provider is down; show a retry message.
- A network `TypeError` (no response) is almost always CORS. In dev, hint that the client's Custom UI URI (Portal: Applications → the client → Custom UI) may not match this origin.
