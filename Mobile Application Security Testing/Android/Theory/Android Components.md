## Intent

An `Intent` is a messaging object used to request an action from another app component. It can start an activity, send a broadcast, or start a service. Intents describe the operation to be performed, and optionally, the data to operate on.

#### Explicit Intent

Used to start a specific component by name (e.g., `MainActivity`).
```java
Intent intent = new Intent(this, DashboardActivity.class);
startActivity(intent);
```

#### Implicit Intent

Used when you do not name the exact class to start. Instead, you declare a general action (e.g., take a photo, view a URL) and the system resolves the best component to handle it.
```java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("https://example.com"));
startActivity(intent);
```

#### Intent with Data

You can pass additional data using extras:
```java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("https://example.com"));
startActivity(intent);
```

#### Intents and Components
1. Activities

Launch a new screen.
```java
Intent i = new Intent(this, SecondActivity.class);
startActivity(i);
```


2. Broadcast Receivers

Send or receive broadcasted messages.
```java
Intent intent = new Intent("com.example.MY_NOTIFICATION");
sendBroadcast(intent);
```

3. Services

Start background operations.
```java
Intent intent = new Intent(this, MyBackgroundService.class);
startService(intent);
```

4. Content Providers

Cannot be started using intents directly. Access is done via ContentResolver.

#### Implicit Intent Vulnerabilities

- Intent Spoofing: Malicious apps send fake intents to exported components.

- Data Leakage: Sensitive data passed in unprotected intents can be read by other apps.

- Pending Intent Hijacking: n attacker modifies a PendingIntent to redirect or execute malicious code.

- Activity Hijacking: An attacker intercepts an implicit intent and shows their own UI instead of the intended one.

---


## Activities
An `Activity` in Android represents a single, focused screen with which the user can interact. It serves as the entry point for user interactions and typically contains a user interface (UI). Activities are central to the Android application lifecycle and manage what the user currently sees and interacts with.

Each activity must be declared in the AndroidManifest.xml file, where developers can define properties such as permissions, intent-filters, and whether the activity is exported.
Lifecycle

An activity has a defined lifecycle managed by the Android system. Common lifecycle methods include:

- onCreate(): called when the activity is first created.

- onStart(): called when the activity becomes visible to the user.

- onResume(): called when the activity starts interacting with the user.

- onPause(), onStop(), onDestroy(): called as the activity loses focus, becomes hidden, or is destroyed.

#### Exported Activities

An activity can be set as `exported="true"` in the manifest. This makes it accessible to other apps through explicit or implicit intents.

Example scenario:
```xml
<activity
    android:name=".DashboardActivity"
    android:exported="true" />
```
If an application has:

- `LoginActivity` (not exported)
- `DashboardActivity` (exported = true)
- `SettingsActivity` (not exported)

An attacker could directly launch `DashboardActivity` using an intent, bypassing the `LoginActivity`. This creates a security vulnerability, as it allows access to parts of the app that should be protected by authentication.


---


## Services
`Services` are used to perform long-running operations in the background.
Types:

- Started Service: Starts with startService(). Continues running even if the component is destroyed.

- Bound Service: Allows components to bind and interact with the service.

```java
Intent serviceIntent = new Intent(this, SyncService.class);
startService(serviceIntent);
```



---


## Broadcast receivers 
A `BroadcastReceiver` is a component that allows Android apps to receive and respond to **broadcasted intents** from the system or other applications. These broadcasts signal that a specific event has occurred (e.g., battery low, network connected, SMS received, etc.).

#### System Broadcasts

Android automatically sends system-wide broadcast intents for many events, such as:

- `Intent.ACTION_BOOT_COMPLETED`
- `Intent.ACTION_BATTERY_CHANGED`
- `Intent.ACTION_AIRPLANE_MODE_CHANGED`

#### Custom Broadcasts

Applications can also send their own broadcasts using `sendBroadcast()`, allowing communication between components or apps.

```java
public class BatteryReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // Handle battery level change
    }
}
```
To register the receiver dynamically:
```java
IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
registerReceiver(new BatteryReceiver(), filter);
```
Or statically in `AndroidManifest.xml`:
```xml
<receiver android:name=".BatteryReceiver">
    <intent-filter>
        <action android:name="android.intent.action.BATTERY_CHANGED" />
    </intent-filter>
</receiver>
```


---


## Content providers
A `ContentProvider` manages access to a **structured set of data**. It enables data sharing **between applications**, exposing data through a **uniform interface using URIs**.

Content providers abstract the data layer and make it accessible via the `ContentResolver` API.

They are particularly useful for:

- Sharing data between apps (e.g., contacts, media, calendar).
- Centralizing access to app-internal databases.

```java
Cursor cursor = getContentResolver().query(
    ContactsContract.Contacts.CONTENT_URI,
    null,       // Projection (columns)
    null,       // Selection (WHERE clause)
    null,       // Selection args
    null        // Sort order
);
```

Each content provider exposes a public URI that other apps can use to query or modify data. For example:

- Contacts: `content://contacts/people`    
- Media: `content://media/external/images/media`

---

## General ExampleAccessing Data Example

#### Example flow: Taking a photo in a social media app

**Step-by-step:**

1. **App sends an explicit intent to open the camera app:**
```java
Intent takePictureIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
if (takePictureIntent.resolveActivity(getPackageManager()) != null) {
    startActivityForResult(takePictureIntent, REQUEST_IMAGE_CAPTURE);
}
```

2. **System checks if the camera app is running or available.**
3. **System starts the camera app (Activity) if needed.**
4. **User takes a photo in the camera app UI (Activity).**    
5. **Camera app sends the captured image back via Intent result.**
6. **Social media app receives the image in `onActivityResult`:**
```java
@Override
protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    if (requestCode == REQUEST_IMAGE_CAPTURE && resultCode == RESULT_OK) {
        Bundle extras = data.getExtras();
        Bitmap imageBitmap = (Bitmap) extras.get("data");
        // Use the photo (display/upload)
    }
}
```

**How components interact:**

- **Activity**: Social media app’s UI sends the intent, handles the returned photo.
    
- **System**: Mediates intent delivery and manages camera app lifecycle.
    
- **Camera App (Activity)**: Handles UI for capturing image.
    
- **Broadcast Receiver**: (Optional) Can listen for system events like media scanning after photo is saved.
    
- **Content Provider**: (Optional) Camera app or system may save the image accessible via content URIs.