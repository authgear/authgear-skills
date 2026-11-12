# Framework: React (SPA)

A client-side React app with no server and no SSR (**not** Next.js). Build output is static files.

## Read before scaffolding (always use the current docs)

- Vite getting started: https://vite.dev/guide/ (`create vite` with the React + TypeScript template)
- React docs: https://react.dev/learn/build-a-react-app-from-scratch
- Router: React Router docs https://reactrouter.com/ (use its current SPA / "declarative" or "data" mode, not framework/SSR mode)
- Vite env variables: https://vite.dev/guide/env-and-mode
- Styling: use whatever the user asks for. If they have no preference, use Tailwind CSS and follow its current Vite install guide: https://tailwindcss.com/docs/installation/using-vite

Use the versions and commands those pages give **today**. Don't reuse versions from memory.

## Requirements the scaffold must meet

- TypeScript in strict mode. A `type-check` script and a `build` script that fails on type errors.
- Config through one module (e.g. `src/config.ts`) that reads `import.meta.env.VITE_AUTHGEAR_ENDPOINT`, plus
  `VITE_BOT_PROTECTION_SITE_KEY` / `VITE_APP_HOME_URL` if they're needed. Commit a `.env.example`. Keep `.env.local` gitignored.
- A fixed dev port in the Vite config, so the localhost Custom UI URI registered in the Portal stays stable.
- Client-side routes for each entry flow in the screen plan, plus `/oauth-callback` when OAuth is reachable,
  plus a catch-all route (not-found / "start from your app" page).
- SPA fallback at the host. Every route must serve `index.html`. Vite dev/preview already does this. For production, see the deploy reference.

## Suggested structure (adapt to the plan)

```
src/
  config.ts                  # env access
  authflow/
    client.ts                # create / input / batchInput / getState, AuthFlowError
    types.ts                 # only the response/input types this UI uses
    useFlow.ts               # runner: current result, submit, history integration, finish redirect
    errors.ts                # reason → message (see error-handling.md)
  screens/                   # one component per screen in the plan, e.g. IdentifyScreen, PasswordScreen, OtpScreen…
  pages/                     # route entries: LoginPage, SignupPage, ForgotPasswordPage, OAuthCallbackPage, NotFound
  components/                # shared UI: Card, Field, SubmitButton, ErrorAlert, ResendButton…
  main.tsx, App.tsx
.authgear/                   # manifest.json, authflow.yaml, flow-map.md (see SKILL.md step 6)
```

## React-specific gotchas

- StrictMode runs effects twice in development. Guard flow creation and the OAuth callback submit with a ref,
  or with an in-flight promise cache, so you don't create two flows or redeem the code twice.
- The `useActionState` / `useFormStatus` pattern works well for screen forms. Keep the `state_token` in runner state, not in DOM inputs.
- Use React Router's `useSearchParams()` / `location.search` to read the authorization query once at entry, then store it (see `ui-implementation.md` §2).
- `window.location.href = …` for `finish_redirect_uri` and OAuth URLs. Router navigation can't leave the SPA.
