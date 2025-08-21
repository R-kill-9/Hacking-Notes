## Secure Flag in Activities

Some Android apps set the `FLAG_SECURE` flag on an Activity to prevent the screen content from being captured (e.g., blocking screenshots or screen recording). This is often used in apps dealing with sensitive information, such as banking or payment applications.

- Purpose: Prevents data leakage through screen captures.
    
- Impact: Users cannot take screenshots of the Activity.
    
- Security Relevance: Indicates that developers want to protect the displayed data.

```kotlin
class SecureActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_secure)

        // Prevents screenshots, screen recording, and view in recent apps
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
}
```

---

## Single Activity with Changing Content

In modern Android development, it is possible for an app to have only **one main Activity** that dynamically changes its content using Fragments, navigation components, or composable screens (Jetpack Compose).

- This design simplifies navigation and lifecycle management.
    
- Instead of multiple Activities, the app manages its UI transitions within one Activity.
    
- Common in apps using the **Single-Activity Architecture** pattern.
    

This means that even if the app only defines one Activity in its manifest, it can still present multiple different screens to the user by swapping or replacing the UI within that Activity.