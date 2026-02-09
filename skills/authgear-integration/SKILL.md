---
name: authgear-integration
description: Integrate Authgear authentication SDK into web and mobile applications. Use when developers request to "add authentication", "integrate Authgear", "implement login/logout", "add auth to React/React Native/Vue/Flutter/Android app", or mention Authgear SDK setup. Supports React SPA, React Native, Android, Flutter, Vue.js, Next.js, iOS, and Ionic with automatic dependency installation, configuration, context provider setup, authentication flows, protected routes, user profile pages, and API integration patterns.
---

# Authgear Integration

## Overview

This skill helps developers integrate Authgear authentication into their applications quickly and correctly. It provides framework-specific guidance, reusable code templates, and common patterns for protected routes, user profiles, API integration, and role-based access control.

## Integration Workflow

### 1. Detect Project Framework

Identify the project type by examining:
- Package files: `package.json`, `pubspec.yaml`, `build.gradle`, `Podfile`
- Project structure: presence of `src/`, `android/`, `ios/`, `lib/` directories
- Configuration files: `vite.config.js`, `next.config.js`, `angular.json`

Common frameworks:
- **React SPA**: `package.json` with `react` and `react-dom`, typically with `vite` or `react-scripts`
- **React Native**: `package.json` with `react-native`, `ios/` and `android/` directories
- **Flutter**: `pubspec.yaml` with `flutter` dependency
- **Android**: `build.gradle` files, `AndroidManifest.xml`
- **Vue.js**: `package.json` with `vue` dependency
- **Next.js**: `package.json` with `next` dependency

### 2. Ask User for Configuration

Use AskUserQuestion to gather required information:

```json
{
  "questions": [
    {
      "question": "Do you have an Authgear project setup? If yes, provide your Client ID.",
      "header": "Client ID",
      "multiSelect": false,
      "options": [
        {
          "label": "I have a Client ID",
          "description": "Provide your Authgear Client ID from the portal"
        },
        {
          "label": "Not yet, help me set it up",
          "description": "Guide me through creating an Authgear project"
        }
      ]
    },
    {
      "question": "What is your Authgear endpoint URL?",
      "header": "Endpoint",
      "multiSelect": false,
      "options": [
        {
          "label": "I have an endpoint",
          "description": "Provide your Authgear endpoint (e.g., https://myapp.authgear.cloud)"
        },
        {
          "label": "Help me find it",
          "description": "Show me where to find my endpoint"
        }
      ]
    }
  ]
}
```

If user doesn't have Client ID or Endpoint, guide them:
- Visit https://portal.authgear.com
- Create a new project or select existing
- Navigate to Applications → Create Application
- Select appropriate application type (Native App for mobile, SPA for web)
- Configure redirect URIs
- Copy Client ID and Endpoint

### 3. Install Dependencies

Based on detected framework:

**React SPA:**
```bash
npm install --save --save-exact @authgear/web
```

**React Native:**
```bash
npm install --exact @authgear/react-native
cd ios && pod install
```

**Flutter:**
```bash
flutter pub add flutter_authgear
```

**Android:**
Add to `build.gradle` - see [references/android.md](references/android.md)

### 4. Configure Environment Variables

Create or update `.env` file (or appropriate config for framework):

**React (Vite):**
```properties
VITE_AUTHGEAR_CLIENT_ID=<CLIENT_ID>
VITE_AUTHGEAR_ENDPOINT=<ENDPOINT>
VITE_AUTHGEAR_REDIRECT_URL=http://localhost:5173/auth-redirect
```

**React (Create React App):**
```properties
REACT_APP_AUTHGEAR_CLIENT_ID=<CLIENT_ID>
REACT_APP_AUTHGEAR_ENDPOINT=<ENDPOINT>
REACT_APP_AUTHGEAR_REDIRECT_URL=http://localhost:3000/auth-redirect
```

For React Native, Flutter, Android: credentials typically hardcoded in config or stored in platform-specific secure storage.

### 5. Implement Core Authentication

Use framework-specific templates from `assets/` and detailed guides from `references/`:

**For React:**
1. Copy `assets/react/UserProvider.tsx` to `src/`
2. Copy `assets/react/AuthRedirect.tsx` to `src/pages/` or `src/components/`
3. Copy `assets/react/useAuthgear.ts` to `src/hooks/`
4. Update routing to include `/auth-redirect` route
5. Wrap app with `UserContextProvider`

See [references/react.md](references/react.md) for complete implementation details.

**For React Native:**
1. Initialize SDK in `App.tsx`
2. Configure platform-specific redirect handling (AndroidManifest.xml, Info.plist)
3. Implement authentication flow with session state management

See [references/react-native.md](references/react-native.md) for complete implementation details.

**For Flutter:**
1. Add SDK initialization in app state
2. Configure platform-specific URL schemes
3. Implement authentication UI

See [references/flutter.md](references/flutter.md) for complete implementation details.

**For Android:**
1. Add SDK dependency
2. Initialize in MainActivity
3. Configure redirect activity in manifest

See [references/android.md](references/android.md) for complete implementation details.

### 6. Implement Requested Features

Based on user requirements, implement common patterns from [references/common-patterns.md](references/common-patterns.md):

**Protected Routes:**
- Use `ProtectedRoute` component (React) from `assets/react/ProtectedRoute.tsx`
- Implement navigation guards for React Native/Flutter
- See examples in common-patterns.md

**User Profile Page:**
- Fetch user info using `authgear.fetchUserInfo()`
- Display user details (ID, email, phone)
- Add settings button using `authgear.open(Page.Settings)`

**API Integration:**
- Use `authgear.fetch()` for automatic token handling
- Or manually add Authorization header with `authgear.accessToken`
- Implement token refresh logic

**Role-Based Access:**
- Extract roles/permissions from user info
- Create permission checking hooks/utilities
- Conditionally render UI based on roles

### 7. Add Login/Logout UI

Create UI components for authentication:

**Login Button:**
```tsx
// React
import { useAuthgear } from './hooks/useAuthgear';

const LoginButton = () => {
  const { login } = useAuthgear();
  return <button onClick={login}>Login</button>;
};
```

**Logout Button:**
```tsx
const LogoutButton = () => {
  const { logout } = useAuthgear();
  return <button onClick={logout}>Logout</button>;
};
```

**Settings Button:**
```tsx
const SettingsButton = () => {
  const { openSettings } = useAuthgear();
  return <button onClick={openSettings}>Settings</button>;
};
```

### 8. Test Integration

Guide user to test:
1. Start development server
2. Click login button → should redirect to Authgear
3. Complete authentication
4. Should redirect back to app at `/auth-redirect`
5. Should then navigate to home page as authenticated user
6. Verify protected routes work
7. Test logout functionality

## Framework-Specific Guides

For detailed implementation instructions, consult these framework-specific references:

- **React SPA**: [references/react.md](references/react.md)
- **React Native**: [references/react-native.md](references/react-native.md)
- **Android**: [references/android.md](references/android.md)
- **Flutter**: [references/flutter.md](references/flutter.md)

## Common Patterns

For implementing specific features, see [references/common-patterns.md](references/common-patterns.md):

- Protected routes and navigation guards
- User profile pages with settings
- API integration with automatic token handling
- Role-based access control

## Quick Setup Examples

### React SPA - Minimal Setup

```tsx
// 1. Install
npm install --save --save-exact @authgear/web react-router-dom

// 2. Wrap app with provider (App.tsx)
import { UserContextProvider } from './UserProvider';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import AuthRedirect from './AuthRedirect';
import Home from './Home';

function App() {
  return (
    <UserContextProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/auth-redirect" element={<AuthRedirect />} />
          <Route path="/" element={<Home />} />
        </Routes>
      </BrowserRouter>
    </UserContextProvider>
  );
}

// 3. Add login button (Home.tsx)
import { useAuthgear } from './hooks/useAuthgear';
import { useUser } from './UserProvider';

function Home() {
  const { login, logout } = useAuthgear();
  const { isLoggedIn } = useUser();

  return (
    <div>
      {isLoggedIn ? (
        <button onClick={logout}>Logout</button>
      ) : (
        <button onClick={login}>Login</button>
      )}
    </div>
  );
}
```

### React Native - Minimal Setup

```tsx
// 1. Install
npm install --exact @authgear/react-native
cd ios && pod install

// 2. Initialize in App.tsx
import authgear, { SessionState } from '@authgear/react-native';
import { useEffect, useState } from 'react';
import { Button, Text, View } from 'react-native';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    authgear.configure({
      clientID: '<CLIENT_ID>',
      endpoint: '<ENDPOINT>',
    }).then(() => {
      authgear.delegate = {
        onSessionStateChange: (container) => {
          setIsLoggedIn(container.sessionState === SessionState.Authenticated);
        },
      };
    });
  }, []);

  const handleLogin = () => {
    authgear.authenticate({ redirectURI: 'com.myapp://host/path' });
  };

  const handleLogout = () => {
    authgear.logout();
  };

  return (
    <View>
      {isLoggedIn ? (
        <Button title="Logout" onPress={handleLogout} />
      ) : (
        <Button title="Login" onPress={handleLogin} />
      )}
    </View>
  );
}

// 3. Configure AndroidManifest.xml and Info.plist (see references/react-native.md)
```

## Resources

- **assets/react/**: Ready-to-use React components (UserProvider, AuthRedirect, ProtectedRoute, useAuthgear hook)
- **references/**: Detailed framework-specific integration guides
- **Authgear Documentation**: https://docs.authgear.com
- **Authgear Portal**: https://portal.authgear.com

## Important Notes

- Always use environment variables for Client ID and Endpoint (never hardcode in React web apps)
- For mobile apps, configure platform-specific URL schemes in AndroidManifest.xml and Info.plist
- Use `useRef` in React 18+ to prevent duplicate authentication in StrictMode
- Call `refreshAccessTokenIfNeeded()` before using access tokens
- Use `authgear.fetch()` for automatic token handling in API calls
