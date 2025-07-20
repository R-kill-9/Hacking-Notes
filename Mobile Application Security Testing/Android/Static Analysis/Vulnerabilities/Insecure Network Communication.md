Insecure network communication occurs when data is transmitted without proper encryption or validation. This exposes apps to various network-layer attacks.

#### Common Issues

- **Data sent over HTTP** instead of HTTPS
- **Unvalidated SSL/TLS certificates**, allowing Man-in-the-Middle (MITM) attacks
- **Weak or missing certificate pinning**
- **Improper session handling** that enables hijacking

#### Risks

- **MITM (Man-in-the-Middle) Attacks**: Attackers can intercept and alter traffic
- **Session Hijacking**: If tokens or session IDs are exposed, attackers can impersonate the user
- **Credential Theft**: Plaintext usernames and passwords can be harvested
- **API Manipulation**: Unencrypted APIs can be replayed, intercepted or spoofed

---

#### Example 1: Java class using HttpURLConnection over HTTP

```java
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*

fun createUnsafeOkHttpClient(): SSLSocketFactory {
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })

    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, SecureRandom())

    return sslContext.socketFactory // INSECURE: Accepts all certs
}
```


#### Example 2: Kotlin code that disables SSL certificate validation
```kotlin
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*

fun createUnsafeOkHttpClient(): SSLSocketFactory {
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })

    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, SecureRandom())

    return sslContext.socketFactory // INSECURE: Accepts all certs
}
```


#### Example 3: Swift code using HTTP (without TLS)
```swift
import Foundation

func sendInsecureRequest() {
    if let url = URL(string: "http://example.com/api/data") { // INSECURE: HTTP
        let task = URLSession.shared.dataTask(with: url) { data, response, error in
            // Handle response
        }
        task.resume()
    }
}
```


---

## URL Scheme Hijacking (iOS/Android)

Mobile apps sometimes register custom URL schemes like `myapp://login`. If not protected properly, other malicious apps can register the same scheme and intercept calls.

#### Example (vulnerable scenario):

```java
<!-- AndroidManifest.xml -->
<intent-filter>
    <data android:scheme="myapp" />
    <action android:name="android.intent.action.VIEW" />
</intent-filter>
```