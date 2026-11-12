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
| Bot protection errors | `pkg/lib/botprotection/errors.go`, plus `BotProtectionRequired` in the API reference |
| Authflow errors (`AuthenticationFlowNotFound`, `SelectAccountSessionChanged`, …) | `pkg/lib/authenticationflow/errors.go`, `pkg/lib/authenticationflow/declarative/error.go` |

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
  `NoAuthenticator`, `MismatchedUser`, `ClaimNotVerifiable`, `IdentityModifyDisabled`.
- `InvalidOTPCode`: `info.cause.kind` is `CodeNotFound` (expired), `InvalidCode` or `UsedCode`.
  Too many wrong attempts returns `RateLimited` instead, and the screen's `failed_attempt_rate_limit_exceeded` becomes true. Prompt for a resend.
- `PasswordPolicyViolated`: `info.causes[]` lists the failed rules. Each cause is
  `{ "Name": "PasswordTooShort", "Info": { … } }`, with capitalized keys because the Go struct has no JSON tags.
  Names: `PasswordTooShort`, `PasswordUppercaseRequired`, `PasswordLowercaseRequired`, `PasswordAlphabetRequired`,
  `PasswordDigitRequired`, `PasswordSymbolRequired`, `PasswordContainingExcludedKeywords`, `PasswordBelowGuessableLevel`,
  `PasswordReused` (`pkg/lib/authn/authenticator/password/policy.go`). Auth UI matches violations exactly this way,
  on `cause["Name"]`: see `NewPasswordPolicyViewModel` in `pkg/auth/handler/webapp/viewmodels/password_policy.go`,
  and `resources/authgear/templates/en/web/authflowv2/__password_policy.html` for the hint list and `Info` keys
  (`min_length`, `min_level`). Mark the matching hints as failed.
- `AccountLockout` carries `info.until` (a timestamp). Show "Try again in m:ss" and disable submit until then.
- `RateLimited` carries **no deadline**, only `info.rate_limit: { name, group }`. Show a generic "Too many attempts, please wait".
  Don't look for `retry_after`-style fields; the server doesn't set them.
- Account status: `DisabledUser`, `DeactivatedUser`, `AnonymizedUser`, `UserOutsideValidPeriod`, `ScheduledDeletionByAdmin`,
  `ScheduledDeletionByEndUser` and `ScheduledAnonymizationByAdmin` come from `check_account_status`. They are terminal. Show an explanation, not a retry.
- `ValidationFailed`: the input shape doesn't match the schema. This is a bug in the UI, not a user error. Log `info.causes`. Show a generic message.
- A network `TypeError` (no response) is almost always CORS. In dev, hint that `x_custom_ui_uri` may not be registered for this origin.
