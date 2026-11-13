# Framework: React (SPA)

A client-side React app with no server and no SSR (**not** Next.js). Build output is static files.

## Read before scaffolding (always use the current docs)

- Vite getting started: https://vite.dev/guide/ (`create vite` with the React + TypeScript template)
- React docs: https://react.dev/learn/build-a-react-app-from-scratch
- Router: React Router docs https://reactrouter.com/ (use its current SPA / "declarative" or "data" mode, not framework/SSR mode)
- Vite env variables: https://vite.dev/guide/env-and-mode
- Styling (the user's answer in SKILL.md step 1b; default Tailwind CSS): Tailwind's current Vite install guide
  https://tailwindcss.com/docs/installation/using-vite. For CSS Modules: https://vite.dev/guide/features#css-modules
- Component library (default Radix UI): Radix Primitives getting started
  https://www.radix-ui.com/primitives/docs/overview/getting-started. Use **Primitives** (unstyled), not Radix Themes,
  and style them with the chosen styling approach. Install only what the docs currently recommend; don't guess package names.
- Translations (default, unless the user asked for another approach): i18next with react-i18next, loading the JSON
  files from `ui-implementation.md` §14. https://react.i18next.com/ and https://www.i18next.com/
- Unit tests: Vitest https://vitest.dev/guide/ (shares the Vite config), with React Testing Library
  https://testing-library.com/docs/react-testing-library/intro/ and a DOM environment for the screen and runner tests.
- Any other library the user names: its own current official docs.

Use the versions and commands those pages give **today**. Don't reuse versions from memory.

## Requirements the scaffold must meet

- TypeScript in strict mode. A `type-check` script and a `build` script that fails on type errors.
- A `test` script that runs the unit tests once (no watch mode), for the agent and for CI (SKILL.md step 4.8).
- Config through one module (e.g. `src/config.ts`) that reads `import.meta.env.VITE_AUTHGEAR_ENDPOINT`, plus
  `VITE_BOT_PROTECTION_SITE_KEY` if they're needed. Commit a `.env.example`. Keep `.env.local` gitignored.
- A fixed dev port in the Vite config, so the localhost Custom UI URI registered in the Portal stays stable.
- Client-side routes for each entry flow in the screen plan, plus `/oauth-callback` when OAuth is reachable,
  plus `/reset-password` when recovery links open the Custom UI, plus a catch-all route (not-found / "start from your app" page).
- SPA fallback at the host. Every route must serve `index.html`. Vite dev/preview already does this. For production, see the deploy reference.

## Suggested structure (adapt to the plan)

```
src/
  config.ts                  # env access
  i18n/                      # setup + locale resolution from ui_locales; locales/<lang>.json (ui-implementation.md §14)
  theme.css                  # design tokens, light + dark (ui-implementation.md §15)
  authflow/
    client.ts                # create / input / batchInput / getState, AuthFlowError
    types.ts                 # only the response/input types this UI uses
    useFlow.ts               # runner: current result, submit, history integration, finish redirect
    errors.ts                # reason → translation key (see error-handling.md)
  screens/                   # one component per screen in the plan, e.g. IdentifyScreen, PasswordScreen, OtpScreen…
  pages/                     # route entries: LoginPage, SignupPage, ForgotPasswordPage, OAuthCallbackPage, NotFound
  components/                # shared UI: Card, Field, SubmitButton, ErrorAlert, ResendButton… (wrapping the component library, if any)
  main.tsx, App.tsx
.authgear/                   # manifest.json, authflow.yaml, flow-map.md (see SKILL.md step 6)
```

## React-specific gotchas

- StrictMode runs effects twice in development. Guard flow creation and the OAuth callback submit with a ref,
  or with an in-flight promise cache, so you don't create two flows or redeem the code twice.
- The `useActionState` / `useFormStatus` pattern works well for screen forms. Keep the `state_token` in runner state, not in DOM inputs.
- Read the authorization query in the **entry route components** (not app-wide in `main.tsx`/`App.tsx`), using React
  Router's `useSearchParams()` / `location.search`, and follow the capture rules in `ui-implementation.md` §2.
- `window.location.href = …` for `finish_redirect_uri` and OAuth URLs. Router navigation can't leave the SPA.
- Use the component library where it helps (dialogs, selects, checkboxes, tabs, toasts), but keep plain `<form>`,
  `<input>` and `<button>` elements for credential fields, so browsers and password managers recognise them
  (`autocomplete="username"`, `"current-password"`, `"new-password"`, `"one-time-code"`). Wrap library components in
  `components/`, so screens don't depend on the library directly.
- Keep the CSP (deploy reference) in sync with the stack: if a library or font loads from a CDN, its domains must be
  allowed in `style-src`/`font-src`/`script-src`. Prefer bundling assets so no extra domains are needed.
