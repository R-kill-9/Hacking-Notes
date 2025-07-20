The `AndroidManifest.xml` file is a crucial component of every Android app. It provides essential information to the Android system before any code is executed.

#### Purposes:

- Declares the **package name**, which must be unique on the device and identifies the application. It prevents the installation of multiple apps with the same package name.
- Declares **app components** (`<activity>`, `<service>`, `<receiver>`, `<provider>`).
- Declares **permissions** required to access protected features (e.g., camera, contacts).
- Specifies **minimum API level** required via `minSdkVersion`.
- Declares **app capabilities**, such as background services or hardware requirements.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />

    <application
        android:label="@string/app_name"
        android:icon="@drawable/icon">

        <activity android:name=".MainActivity" />
        <service android:name=".MyService" />
        <receiver android:name=".MyReceiver" />
        <provider android:name=".MyContentProvider" />
        
    </application>
</manifest>
```
> ⚠ Not all components are always declared in the manifest explicitly; some may be registered dynamically within the code.

---


## Permissions Analysis

Permissions control access to restricted APIs or system features. Some permissions are **normal**, while others are **dangerous** or **signature-protected**.

For pentesting purposes, we focus on those that may:

- Expose sensitive user data    
- Enable background activity
- Allow system modification    
- Facilitate remote access


#### Device Administration & Accessibility Abuse

These can allow powerful control over the device, enabling persistence or surveillance:

```xml
<uses-permission android:name="android.permission.BIND_DEVICE_ADMIN" />
<uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
```


#### Data Theft & Privacy Risks

Permissions that can expose private user data:

```xml
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.READ_CALL_LOG" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
<uses-permission android:name="android.permission.CAMERA" />
```

#### File System & Storage Exploits

Permissions that grant access to shared or external storage:
```xml
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
```

#### Background & Hidden Activities

Used to create overlays, foreground services or avoid battery restrictions:
```xml
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
<uses-permission android:name="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />
```


#### Critical System Permissions

Can modify core OS behavior or perform privileged actions:
```xml
<uses-permission android:name="android.permission.WAKE_LOCK" />
<uses-permission android:name="android.permission.REBOOT" />
<uses-permission android:name="android.permission.INSTALL_PACKAGES" />
<uses-permission android:name="android.permission.DELETE_PACKAGES" />
```

#### Permission Groups and Custom Permissions

Apps can define custom permission groups to organize related permissions.

Example of a **custom permission group** and permission:

```xml
<!-- Define a permission group -->
<permission-group
    android:name="com.example.permission-group.SYSTEM_TOOLS"
    android:label="System Tools"
    android:description="Access system-level tools" />

<!-- Define a permission and assign it to the above group -->
<permission
    android:name="com.example.permission.SYSTEM_MONITOR"
    android:protectionLevel="signature|system"
    android:permissionGroup="com.example.permission-group.SYSTEM_TOOLS" />
```

- Permissions **not starting with `android.permission`** are custom-defined by third-party apps or vendors.

- `protectionLevel="signature|system"` means only apps signed with the same certificate or pre-installed system apps can request the permission.


#### Reference 

Android permission protection levels and security scores:

🔗 [Android Developer Guide – Permissions](https://developer.android.com/reference/android/Manifest.permission)

---

## Exported Components

In Android, a component is considered **exported** when it is accessible by other apps.

This is defined via:
```xml
<activity android:name=".SomeActivity" android:exported="true" />
```

If `exported="true"`, the component can be invoked by other apps via **Intents** — even potentially malicious ones. If no proper validation exists, this could lead to privilege escalation, UI bypass or code execution.

#### Exported Components Risk Table
| Component Type        | Risk                                                   | Mitigation                                                               |
| --------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------ |
| **Exported Activity** | UI bypass (e.g., skip login), Intent injection         | Validate all input, use permissions or restrict exported=false           |
| **Exported Service**  | Arbitrary code execution or misuse of background logic | Require permissions, validate Intent actions                             |
| **Exported Receiver** | Triggering system-level events, intent spoofing        | Use permission-based access control, verify sender                       |
| **Exported Provider** | Unauthorized access to app data via `content://` URIs  | Set `android:exported="false"` unless necessary, enforce URI permissions |

--- 


## Debuggable Apps

An app marked as `android:debuggable="true"` can be attached to via **`adb`**, allowing inspection of memory, logs, and execution.

This should **never** be enabled in production.

```xml
<application android:debuggable="true" />
```

Risk: Full control of the app’s internals during runtime.

**Mitigation:** Ensure this is **false** or removed in production builds.


---

## Backup Enabled

If `android:allowBackup="true"` is enabled, app data can be extracted via:

```bash
adb backup -f backup.ab com.example.myapp
```

Risk: May expose internal data (preferences, local DB, tokens) unless explicitly excluded via android:fullBackupContent.

**Mitigation:** Set android:allowBackup="false" or explicitly configure backup exclusions.


---

## Cleartext Traffic Allowed

Cleartext (non-HTTPS) traffic can be intercepted via MITM attacks.

Check:
```xml
<application android:usesCleartextTraffic="true" />
```

Risk: Sensitive data sent over unencrypted HTTP.

**Mitigation:** Use HTTPS and set `usesCleartextTraffic="false"` in production.


---
## Grant URI Permission

Apps may **temporarily share access** to files or data using content URIs, e.g.:

```less
content://com.example.app.provider/data/123
```

This mechanism avoids exposing full file paths and enables **controlled inter-app data sharing**.

Permissions are granted via:
```java
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
```

Or in XML:
```xml
<grant-uri-permission android:pathPattern=".*" />
```

Risks:

- If misconfigured, **any app** can access protected data via content URIs.
- May lead to leakage of files, photos, or database content.

**Mitigation:** Only grant permissions to trusted apps, avoid wildcard `pathPattern` usage, and enforce proper URI validation in content providers.



---

## Uses-Feature

Used to declare hardware or software features the app uses.

```xml
<uses-feature android:name="android.hardware.telephony" android:required="false" />
```
- If `android:required="false"`, the app will still be visible on devices without that feature (e.g., tablets, Android Auto).

- If `true`, only devices with the specified feature can install the app.

