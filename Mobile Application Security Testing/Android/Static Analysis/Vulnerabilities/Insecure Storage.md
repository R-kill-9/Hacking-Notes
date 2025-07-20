**Insecure storage** occurs when sensitive data is stored locally on the device in locations that are not properly protected. Attackers with access to a rooted or jailbroken device—or through app data extraction techniques—can retrieve this information easily.

#### Common insecure storage locations on Android

- **SharedPreferences**: Often used for simple key-value storage, but not encrypted by default.
- **External Storage**: Files saved here are world-readable and accessible by any app with storage permissions.
- **SQLite Databases**: If not encrypted, databases can be dumped or queried directly from the device.
- **Log files, cache, or temp files**: Sometimes used unintentionally to store sensitive information.

---

#### Example 1: Insecure credential storage using SharedPreferences (Java)

```java
public class LoginActivity extends AppCompatActivity {
    void saveCredentials(String username, String password) {
        SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("username", username);
        editor.putString("password", password); // INSECURE: storing plain-text password
        editor.apply();
    }
}
```

**Problem:** SharedPreferences is stored in `/data/data/<package>/shared_prefs/` and can be accessed on rooted devices or emulators.

---

#### Example 2: Insecure data saved to external storage (Kotlin)
```kotlin
fun saveTokenToExternalStorage(token: String) {
    val fileName = "auth_token.txt"
    val file = File(Environment.getExternalStorageDirectory(), fileName)
    file.writeText("Token: $token") // INSECURE: world-readable file
}
```
**Problem:** External storage (`/sdcard/`) is accessible by other apps and file managers. This exposes sensitive data like auth tokens, session IDs, or API keys.