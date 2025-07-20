Logging is essential for debugging, monitoring and auditing in mobile applications. However, **insecure logging** occurs when sensitive data is improperly written to system logs, exposing it to unauthorized parties.

This issue is particularly dangerous on **compromised devices** (e.g. rooted or jailbroken), where apps or other processes may access logs stored in the system.

#### Risks

- Exposes internal application logic, session tokens, API responses, credentials, and personal user data
- Logs may be accessible via `logcat` (Android) or system logs (iOS), especially on compromised devices.
```bash
adb shell
logcat
```



---

#### Example 1: Insecure logging of sensitive user data (Java - Android)

```java
public class LoginActivity extends AppCompatActivity {
    void login(String username, String password) {
        Log.d("Login", "User: " + username + " Password: " + password); // BAD PRACTICE
        // Auth logic here
    }
}
```
Logs like this may be accessed using `adb logcat`, leaking passwords in plaintext.

#### Example 2: Insecure logging in Swift
```swift
func authenticate(user: String, password: String) {
    print("Authenticating user: \(user) with password: \(password)") // INSECURE
    // Perform authentication
}
```

On jailbroken devices, these logs can be accessed from the system log files.

#### Example 3: Insecure logging in Objective-C
```swift
- (void)loginWithUsername:(NSString *)username password:(NSString *)password {
    NSLog(@"Login attempt: %@ / %@", username, password); // INSECURE
    // Perform login logic
}
```
This data will be visible in device logs or on macOS Console if the app is running in debug mode.