# Android SDK Integration

## Requirements

- Android 5.0 (API 21) or higher
- Android Studio
- Kotlin or Java

## Installation

Add JitPack repository to `settings.gradle`:

```groovy
dependencyResolutionManagement {
  repositories {
    maven { url 'https://jitpack.io' }
  }
}
```

Add dependency to `app/build.gradle`:

```groovy
dependencies {
  implementation 'com.github.authgear:authgear-sdk-android:2024-12-11.0'
}
```

Enable Java 8+ desugaring:

```groovy
android {
  compileOptions {
    coreLibraryDesugaringEnabled true
  }
}

dependencies {
  coreLibraryDesugaring 'com.android.tools:desugar_jdk_libs:1.1.5'
}
```

## Portal Configuration

1. Create Native App in Authgear Portal
2. Define custom URI scheme (e.g., `com.example.myapp://host/path`)
3. Add as Authorized Redirect URI
4. Note Client ID and Endpoint

## SDK Initialization

In `MainActivity.kt`:

```kotlin
import com.authgear.core.Authgear
import com.authgear.core.OnConfigureListener

class MainActivity : AppCompatActivity() {
    private lateinit var authgear: Authgear

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        authgear = Authgear(
            application = application,
            clientId = "<CLIENT_ID>",
            endpoint = "<AUTHGEAR_ENDPOINT>"
        )

        authgear.configure(object : OnConfigureListener {
            override fun onConfigured() {
                // Configuration successful
            }

            override fun onConfigurationFailed(throwable: Throwable) {
                Log.e("Authgear", "Configuration failed", throwable)
            }
        })
    }
}
```

## Manifest Configuration

Add to `AndroidManifest.xml`:

```xml
<activity
    android:name="com.authgear.core.OAuthRedirectActivity"
    android:exported="true"
    android:launchMode="singleTask">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:scheme="com.example.myapp"
            android:host="host"
            android:pathPrefix="/path" />
    </intent-filter>
</activity>
```

## Authentication

```kotlin
import com.authgear.core.OnAuthenticateListener

fun authenticate() {
    authgear.authenticate(
        redirectUri = "com.example.myapp://host/path",
        listener = object : OnAuthenticateListener {
            override fun onAuthenticated(userInfo: UserInfo?) {
                // User authenticated successfully
            }

            override fun onAuthenticationFailed(throwable: Throwable) {
                Log.e("Authgear", "Authentication failed", throwable)
            }
        }
    )
}
```

## Logout

```kotlin
import com.authgear.core.OnLogoutListener

fun logout() {
    authgear.logout(object : OnLogoutListener {
        override fun onLoggedOut() {
            // User logged out successfully
        }

        override fun onLogoutFailed(throwable: Throwable) {
            Log.e("Authgear", "Logout failed", throwable)
        }
    })
}
```

## Fetch User Info

```kotlin
import com.authgear.core.OnFetchUserInfoListener

fun fetchUserInfo() {
    authgear.fetchUserInfo(object : OnFetchUserInfoListener {
        override fun onFetchedUserInfo(userInfo: UserInfo) {
            val userId = userInfo.sub
            // Use user info
        }

        override fun onFetchingUserInfoFailed(throwable: Throwable) {
            Log.e("Authgear", "Fetch user info failed", throwable)
        }
    })
}
```

## Access Tokens

Before making API calls, refresh token if needed:

```kotlin
try {
    authgear.refreshAccessTokenIfNeededSync()
    val accessToken = authgear.accessToken

    // Use token in API calls
    val request = Request.Builder()
        .url("https://api.example.com/data")
        .header("Authorization", "Bearer $accessToken")
        .build()
} catch (e: Exception) {
    Log.e("Authgear", "Token refresh failed", e)
}
```

## Open Settings Page

```kotlin
import com.authgear.core.Page

authgear.open(Page.SETTINGS)
```

## Session State

Check session state:

```kotlin
val isAuthenticated = authgear.sessionState == SessionState.AUTHENTICATED
```
