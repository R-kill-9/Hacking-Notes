**JADX** is a tool that decompiles Android APK files into **readable Java or Kotlin source code**. It’s useful for reverse engineering apps and performing manual security audits.

## Installation
1. Download the latest release:   [https://github.com/skylot/jadx/releases](https://github.com/skylot/jadx/releases)
2. Extract the archive and run:
```bash
./bin/jadx-gui
```

## Loading an APK

1. First, **extract the APK** (you can pull it from a device):
```bash
adb shell pm list packages
adb shell pm path com.target.app
adb pull /data/app/com.target.app/base.apk
```
2. Open `jadx-gui`, load the `base.apk`.
3. The decompiled code will appear in a tree view on the left (organized by package).

## What to Look for During Code Review

#### Hardcoded Secrets / Keys

- API keys
- Encryption keys
- Credentials
- URLs

#### Exported Components

Inspect the `AndroidManifest.xml`:

- Are any Activities, Services, or BroadcastReceivers exported unnecessarily?
- Do they lack permissions?

```xml
<activity android:exported="true" />
```
This could allow attackers to launch internal components.

#### Insecure Network Communications

- Hardcoded IPs or HTTP URLs (instead of HTTPS)
- Custom `HostnameVerifier` or `TrustManager` that disables SSL checks.

#### Insecure Storage

Look at `SharedPreferences`, `FileOutputStream`, or databases.

- Sensitive data saved in plaintext
- `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE`

#### Root / Debug Checks

Validate if the app performs checks to detect:

- Rooted devices
- Debugging tools
- Emulators

```java
Build.FINGERPRINT.contains("generic")
Debug.isDebuggerConnected()
```