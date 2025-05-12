##  AndroidManifest.xml  
This file defines the app's components (activities, services, broadcast receivers, etc.), required permissions, and security-related configurations. It also declares:

- `minSdkVersion`: The minimum Android version the app can run on.  
- `targetSdkVersion`: The Android version the app is optimized for.


---

## Intents
**Intents** are message objects used to request actions from other components or applications in Android. They enable communication between components and allow developers to start activities, services, or send broadcasts.

#### Implicit Intents

Implicit intents do not specify the target component. Instead, they declare a general action to perform (e.g., viewing a webpage, sending an email). Android resolves which component can handle the action.

An intent is created using the `Intent` constructor:
```java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("https://example.com"));
startActivity(intent);
```

The `extra` is the portion of the intent that carries additional data:
```java
Intent intent = new Intent(Intent.ACTION_SEND);
intent.putExtra(Intent.EXTRA_TEXT, "Message text");
```

For an app to receive an implicit intent, its `AndroidManifest.xml` must declare an `<intent-filter>` with the corresponding action and category:
```xml
<activity android:name=".TargetActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="text/plain" />
    </intent-filter>
</activity>
```

**Intent resolution** is the process Android uses to find a component that can handle a given intent based on the filters declared in installed apps.

#### Explicit Intents

Explicit intents specify the exact component (class) to start. These are typically used for internal communication between app components.

```java
Intent intent = new Intent(this, TargetActivity.class);
startActivity(intent);
```

#### Broadcast Intents

Broadcast intents are used to send messages system-wide. They can be received by multiple apps.

There are two types:

- **Normal broadcasts**: Sent asynchronously.

- **Ordered broadcasts**: Sent in a defined order, where each receiver can propagate or abort the broadcast.

```java
Intent intent = new Intent("com.example.CUSTOM_ACTION");
sendBroadcast(intent, "com.example.permission.MY_PERMISSION");
```

**Sticky broadcasts** remain available after being sent, allowing future receivers to get the data. These are deprecated and should be avoided due to security and lifecycle concerns.

#### Pending Intents

Pending intents allow other apps (or the system) to perform actions on behalf of your application, using its identity and permissions.

They are constructed with a predefined intent and the type of action (activity, broadcast, or service):
```java
Intent intent = new Intent(this, AlarmReceiver.class);
PendingIntent pendingIntent = PendingIntent.getBroadcast(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
```


If the provided intent is not explicit, a malicious app could craft an intent that gets executed with your app’s privileges. Therefore, always use explicit intents in pending intent constructions to reduce security risks.


---

## Components
**Components** is a generic term used to describe the most common building blocks of Android applications. These include:

- Activities
- Services
- Broadcast Receivers
- Content Providers

Each component is implemented in Java/Kotlin and must be declared in the application's `AndroidManifest.xml`.

#### Activities

Activities represent visual screens with which users interact. They display UI elements such as buttons, images, text fields, etc.

Most applications expose at least one activity that can be launched via an `Intent`, often acting as an entry point into the app.


#### Services

Services are used to perform long-running operations in the background without a user interface.

- They are started using `startService()` and stopped using `stopService()`.
- A service may also be **bound** to allow communication with other components.

Because services can be triggered by external input (intents), they must be carefully validated. The first place to inspect for vulnerabilities is typically the intent passed to the `onStartCommand()` method.


#### Broadcast Receivers

Broadcast receivers are components that listen for broadcasted intents from the system or other apps.

- **Static receivers** are declared in the manifest.
- **Dynamic receivers** are registered at runtime using `registerReceiver()`.

They are commonly used to react to system events (e.g., device boot, network change) or messages sent by other apps. Since they receive input from external sources, they must validate all data received via the intent.


#### Content Providers

Content Providers allow applications to share **structured data**, such as data from relational databases, with other apps in a secure and managed way.

They are declared in the `AndroidManifest.xml` with attributes like:
```xml
<provider
    android:name=".MyProvider"
    android:authorities="com.example.provider"
    android:exported="true"
    android:readPermission="com.example.READ_PERMISSION"
    android:writePermission="com.example.WRITE_PERMISSION" />
```

Security for content providers is enforced through:

- The `android:exported` flag (determines if other apps can access it).
- `readPermission` and `writePermission` attributes to control access levels.
- The use of `grantUriPermissions`, which allows apps to **temporarily access** specific URIs when given explicit permission.

Example for URI permission grant via intent:
```java
intent.setData(uri);
intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
```


---

## Deep links 
**Deep links** allow an application to respond to URLs and trigger an intent from a web link, email, or another app. This enables users to navigate directly to specific content or features within an app.

To support deep links, you must declare an `<intent-filter>` in the `AndroidManifest.xml` of the target activity.

A proper intent filter should include the following elements:
```xml
<activity android:name=".DeepLinkActivity">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />

        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />

        <data
            android:scheme="https"
            android:host="example.com"
            android:pathPrefix="/path" />
    </intent-filter>
</activity>
```

- The `android.intent.action.VIEW` action indicates that the activity can be launched via a URL.

- The `android.intent.category.BROWSABLE` category allows the intent to be invoked from a browser or other web-based source.

- The `android:autoVerify="true"` attribute enables Android App Links verification.


> **Security note**: As with any externally supplied input, data received via a deep link must be validated and sanitized before use. Unvalidated deep link input could lead to component misuse, data leaks, or code execution via unsafe handling of parameters.


---

## AIDL (Android Interface Definition Language)

AIDL is a language used in Android to define the programming interface that a **service exposes to other applications**. It enables **Inter-Process Communication (IPC)** between different apps or between apps and system services.

This is primarily used in **bound services**, which allow one app to bind to a service in another app and directly call its methods.

#### Bound Services and onBind()

When a client (app) wants to connect to a bound service, the Android system calls the service’s `onBind()` method. This method returns an `IBinder` object that defines the interface the client can use to interact with the service.

A simplified example:
```java
public class MyService extends Service {
    private final IMyAidlInterface.Stub binder = new IMyAidlInterface.Stub() {
        public int getData() {
            return 123;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }
}
```
The `.aidl` file would define the interface `IMyAidlInterface` that both client and service must understand.

#### Security Implications

When exposing a service using AIDL:

- **Review the `onBind()` logic**, as it is the entry point to the service.
- Follow the flow of execution from the binder interface to determine what functionality is exposed.
- If the service performs sensitive actions, ensure proper **permission checks** are implemented.

Check the `AndroidManifest.xml` for services that are exported:
```xml
<service
    android:name=".MyService"
    android:enabled="true"
    android:exported="true"
    android:permission="com.example.PERMISSION_USE_SERVICE">
    <intent-filter>
        <action android:name="com.example.MY_SERVICE" />
    </intent-filter>
</service>
```


---


## Messenger 
**Messenger** is another form of Inter-Process Communication (IPC) in Android, built on top of the Binder framework. It is typically used to send messages between applications or components in a thread-safe way.

Messenger is implemented as a **bound service**, and the communication is managed through the `onBind()` method, which returns a `Messenger` object.
```java
class MyService extends Service {
    final Messenger messenger = new Messenger(new IncomingHandler());

    class IncomingHandler extends Handler {
        @Override
        public void handleMessage(Message msg) {
            // Process incoming messages
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return messenger.getBinder();
    }
}
```

To communicate with this service, a client binds to it and sends `Message` objects to the service via the `Messenger`.

In order to restrict access to the service, appropriate **permissions must be declared** in the `AndroidManifest.xml` file:

```xml
<service
    android:name=".MyService"
    android:exported="true"
    android:permission="com.example.PERMISSION_USE_MESSENGER" />
```
Messenger is suitable for **one-way communication** or when message queues are preferred over direct method invocation.


---

## Binder

The **Binder** is the low-level IPC mechanism used by Android. It is a **kernel-level driver** that enables communication between processes by moving data from one process’s memory space to another securely and efficiently.

Binder provides the underlying transport for:

- Services (`AIDL`, `Messenger`, `ContentProviders`)
- System calls between apps and the Android framework

Almost all high-level IPC mechanisms in Android (like `Messenger`, `AIDL`, and bound services) are **abstractions over Binder**.

---

## Permissions
**Permissions** in Android are a fundamental part of the system's security model. They are used to restrict access to sensitive features and data.

#### Requested Permissions

Requested permissions are the typical permissions that a user is prompted to grant when installing or running an app. These are declared using the `<uses-permission>` tag in the `AndroidManifest.xml` file.
```xml
<uses-permission android:name="android.permission.INTERNET" />
```

This tag can also include the `android:maxSdkVersion` attribute to specify the highest API level for which the permission is requested.
```xml
<uses-permission
    android:name="android.permission.READ_SMS"
    android:maxSdkVersion="22" />

```

Only permissions declared in the manifest will be recognized and requested by the system.


#### Custom Permissions

Applications can define their own **custom permissions** to restrict access to specific components or actions within their app. This is done using the `<permission>` tag in the manifest.

```xml
<permission
    android:name="com.example.permission.MY_CUSTOM_PERMISSION"
    android:protectionLevel="signature"
    android:permissionGroup="android.permission-group.COST_MONEY" />
```
Custom permissions are then referenced in components like services, providers, or activities using attributes such as `android:permission`.



#### Protection Levels

The `android:protectionLevel` attribute determines how a permission is granted and who can request it. There are four main protection levels:

- **normal**  
Granted automatically if requested. Used for low-risk permissions (e.g., access to the internet).
- **dangerous**  
Requires user approval at install time or runtime (from Android 6.0+). These permissions involve access to private data or system features (e.g., contacts, camera).
- **signature**  
Only granted if the requesting app is signed with the same certificate as the app defining the permission.
- **signatureOrSystem** (deprecated)  
Previously allowed access to apps signed with the same certificate or pre-installed as part of the system. This is now discouraged and replaced by proper privilege handling.

---
## WebViews
**WebViews** are embedded web browsers used within Android applications. They are capable of rendering HTML and executing JavaScript. The content displayed in a WebView can be:

- Loaded from remote sources (e.g., a website),
- Loaded from local files within the application (e.g., assets or resources).

Due to their ability to execute external and potentially untrusted content, WebViews can introduce various security risks if not configured properly.


#### Types

There are two main classes used to interact with and customize the behavior of WebViews:

- **WebViewClient**: Handles events like page navigation and loading.
    - Does not support `alert()` JavaScript functions by default.
    - Many common XSS payloads using `alert()` will not work if only WebViewClient is used.
- **WebChromeClient**: Provides support for richer web features such as JavaScript dialogs (e.g., `alert()`, `confirm()`), progress updates, and more.

Developers often override these clients to customize or restrict behavior for security reasons.

#### JavaScript

JavaScript support in WebViews is **disabled by default** for security.
```java
webView.getSettings().setJavaScriptEnabled(true);\
```

Allowing JavaScript increases the risk of XSS, especially when displaying untrusted or external content. It should be enabled only if absolutely necessary and handled with care.

#### Content Provider Access

WebViews can access Android content providers using `content://` URIs. This access is controlled by:
```java
webView.getSettings().setAllowContentAccess(true);
```
If enabled, this may expose sensitive application data if the WebView loads malicious or manipulated content.



#### File System Access

WebViews can also load content from the local file system using `file://` URIs. This can be a source of vulnerabilities, especially if local untrusted files are loaded.

Control file access using:
```java
webView.getSettings().setAllowFileAccess(false);
```
> Note: This does **not** prevent access to files from the `assets/` or `res/` directories.