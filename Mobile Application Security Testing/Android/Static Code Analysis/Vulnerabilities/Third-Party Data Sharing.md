Mobile apps often integrate third-party SDKs and services for analytics, ads, crash reporting or social media features. These SDKs may **collect and transmit sensitive user data** without proper user consent, creating **privacy and security risks**.


#### Why it’s a problem

- Developers may unknowingly leak data through third-party libraries.
- Sensitive data like **location**, **device identifiers**, **contacts**, or **behavioral data** may be collected.
- Violates user privacy and may breach regulations (e.g., GDPR, CCPA).
- Difficult to audit proprietary SDKs (closed-source).
- SDKs may establish **direct network connections**, bypassing app-level security.

---

## How to detect third-party data sharing

#### 1. Review AndroidManifest.xml

- Look for SDK-related permissions (`INTERNET`, `ACCESS_FINE_LOCATION`, `READ_PHONE_STATE`, etc.)
- Check for custom components: `<service>`, `<receiver>`, `<provider>`

#### 2. Review network/API calls

- Analyze HTTP traffic with tools like **mitmproxy**, **Burp Suite**, **Frida**
- Look for connections to third-party domains (e.g., `*.facebook.net`, `*.firebaseio.com`, `*.adjust.com`)

#### 3. Review imported classes and SDKs

- Look for references to suspicious packages (`com.facebook.`, `com.adjust.`, `com.onesignal.`, etc.)
- Use tools like **MobSF**, **jadx** or **apktool** to statically analyze the APK

---

#### Example 1: Java code sending data to a third-party endpoint
```java
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class AnalyticsReporter {
    public void sendEvent(String userId, String event) throws Exception {
        URL url = new URL("https://analytics.thirdparty.com/track"); // Third-party endpoint
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        String body = "user=" + userId + "&event=" + event;
        OutputStream os = conn.getOutputStream();
        os.write(body.getBytes());
        os.close();
        conn.getInputStream(); // Send request
    }
}
```

#### Example 2: Kotlin code leaking IMEI (device ID)

```kotlin
import android.content.Context
import android.telephony.TelephonyManager
import java.net.URL

fun leakDeviceId(context: Context) {
    val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
    val imei = telephonyManager.imei // Requires READ_PHONE_STATE permission

    // Send IMEI to third-party server
    val url = URL("https://tracker.thirdparty.com/collect?imei=$imei")
    val connection = url.openConnection()
    connection.getInputStream()
}
```