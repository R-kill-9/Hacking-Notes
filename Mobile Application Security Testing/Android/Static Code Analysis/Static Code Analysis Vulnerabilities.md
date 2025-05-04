## Tracking Intents and Extras Through the App

The `AndroidManifest.xml` defines the **intents** and **extras** that can be accepted as inputs by an app from other apps on the device. This also determines the behavior of components such as:

- WebViews
- File storage
- Activities
- Services
- Broadcast Receivers
- Content Providers

This information is useful for identifying potential entry points for attackers.

> If any concept is unclear, it is recommended to check the theory folder for fundamental Android code concepts.

---

## SQL Injections

**SQL Injection** is a vulnerability that allows an attacker to manipulate database queries by injecting malicious SQL code into input fields or other entry points that interact with the app’s database.

This is especially relevant in Android apps when working with **ContentProviders**, as they expose database operations via URIs handled by a **ContentResolver**. If the implementation of the ContentProvider constructs SQL queries using untrusted input (e.g., URI paths or query parameters), it can become vulnerable to injection.

### Example (Vulnerable Code)

```java
// Inside a ContentProvider
public Cursor query(Uri uri, ...) {
    String selection = uri.getLastPathSegment(); // e.g., attacker-controlled
    String query = "SELECT * FROM users WHERE username = '" + selection + "'";
    return db.rawQuery(query, null);
}
```
If the attacker crafts a URI like:
```bash
content://com.example.provider/users/' OR '1'='1
```
The resulting SQL becomes:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1'
```
This returns all rows, bypassing access control.

#### Prepared Statements 
Prepared statements protect against SQL injection by safely binding user input.
```java
public Cursor query(Uri uri, ...) {
    String username = uri.getLastPathSegment();
    String query = "SELECT * FROM users WHERE username = ?";
    return db.rawQuery(query, new String[]{username});
}
```

#### ContentResolver and Content URIs

A **ContentResolver** is an object that handles incoming URIs and performs CRUD operations by communicating with the appropriate `ContentProvider`.

A typical content URI is structured as follows `scheme://authority/path/index`:

```java
content://com.example.provider/books/1
```

- **Scheme**: Usually `content`
- **Authority**: The content provider's name (`com.example.provider`)
- **Path**: The table or resource (`books`)
- **Index**: Record identifier (`1`)

To discover content URIs used by an app, you can inspect the `classes.dex` file:
```bash
strings classes.dex | grep "content://"
```

---

## Path Traversal

Path traversal is a vulnerability that allows an attacker to access files outside the intended directory by manipulating file paths.

If a `ContentProvider` is improperly exposed, an attacker might exploit it like this:

```bash
content://com.example.reader.fileprovider/../../../../etc/passwd
```

This bypasses directory restrictions and can be used to read arbitrary files from the file system.


---

## Vulnerable Activities

**Activities** are the visual elements or screens that users interact with in Android. They can become vulnerable when sensitive operations or data are exposed to other apps without proper access controls.

#### Exported Activity Without Permissions

If an activity is declared as `exported="true"` in the `AndroidManifest.xml` and does not specify any `android:permission`, it allows **any other application** to send an intent to it and launch that activity.

#### Example: AndroidManifest.xml

```xml
<activity
    android:name=".ExportedActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="com.example.START_ACTIVITY"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

#### Exploitable Condition

If the activity returns data via `setResult()` and finishes using `finish()`, an attacker can launch it and receive sensitive data.

```java
public class ExportedActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent resultIntent = new Intent();
        resultIntent.putExtra("token", "sensitive_auth_token");
        setResult(RESULT_OK, resultIntent);
        finish();
    }
}
```

Any app can start this activity and intercept the `token` by using `startActivityForResult()`.

---

## Vulnerable Broadcast Receivers

**Broadcast Receivers** are components designed to respond to broadcasted intents. Vulnerabilities arise when:

- They are exported without restrictions.
- They process data from intents without validation.
- They trigger sensitive functionality or leak information.

#### Example: Exported Receiver Without Permission

**AndroidManifest.xml**

```xml
<receiver android:name=".PasswordReceiver"
          android:exported="true">
    <intent-filter>
        <action android:name="com.example.SEND_PASSWORD"/>
    </intent-filter>
</receiver>
```

**PasswordReceiver Class**

```java
public class PasswordReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String password = intent.getStringExtra("password");
        Intent i = new Intent(context, MainActivity.class);
        i.putExtra("password", password);
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(i);
    }
}
```

**MainActivity Reaction**

```java
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String receivedPass = getIntent().getStringExtra("password");
        if (receivedPass != null) {
            // Set password or change state
            // For example:
            AuthManager.setPassword(receivedPass);
        }
    }
}
```

**Impact:** Any app can send a broadcast with a fake password and change the app's internal authentication state.

---

## Vulnerable Services

**Services** are components that perform background operations. A service becomes vulnerable when it is exported and handles intents insecurely

**Exported Service in Manifest**
```xml
<service
    android:name=".ExampleService"
    android:exported="true" />
```
This configuration allows **any app** to start the service and pass input.

#### Vulnerable Service Implementation
```java
public class ExampleService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String filename = intent.getStringExtra("filename");
        File file = new File(getFilesDir(), "private.txt");

        try {
            FileOutputStream fos = new FileOutputStream(file, true);
            fos.write(("Checked: " + filename + "\n").getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Simulate a command like 'find /' (insecure behavior)
        if (new File("/sdcard/" + filename).exists()) {
            Log.d("ExampleService", "File exists: " + filename);
        }

        return START_NOT_STICKY;
    }
}
```

**Impact:**

- Any app can start this service and trigger internal file write operations.
- Sensitive file operations (`/data/data/...`) are triggered without restrictions.
- A potential **information leak** or **privilege escalation** vector if combined with other flaws.


---

## Shared Preferences

Android provides multiple ways to store local data. One common method is using **Shared Preferences**, which stores key-value pairs in an XML file. The preferences file is saved at `/data/data/<package_name>/shared_prefs/`.

An attacker could access this file via device backup methods, root access, or ADB if the device is insecure or debugging is enabled. Sensitive information such as tokens, credentials, or user settings should **not** be stored in plaintext in Shared Preferences.

### Example: Writing to Shared Preferences

```java
SharedPreferences prefs = getSharedPreferences("user_settings", MODE_PRIVATE);
SharedPreferences.Editor editor = prefs.edit();
editor.putString("auth_token", "secret_token_123");
editor.apply();
```
**Resulting File (user_settings.xml)**
```xml
<map>
    <string name="auth_token">secret_token_123</string>
</map>
```


---
## Local Databases

Android apps can store structured data using **SQLite databases**, typically located at `/data/data/<package_name>/databases/`.

You can use the `sqlite3` binary (found in `android/sdk/platform-tools/`) to interact with these databases.

#### Steps to Inspect a Database:

1. Navigate to the app’s data directory:

```bash
cd /data/data/<package_name>/databases/
```

2. Open the database:
```bash
sqlite3 my_database.db
```

3. List all tables:
```bash
.tables
```

4. Dump a table's content:
```bash
.dump users
```

5. Run standard SQL queries:
```bash
SELECT * FROM users WHERE is_admin = 1;
```

If the app stores unencrypted sensitive information such as passwords, tokens, or personal user data, it may be exposed if the attacker can access the database files (e.g., through rooted devices or backups).