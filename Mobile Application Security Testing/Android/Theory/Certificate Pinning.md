Certificate Pinning is a security technique used in mobile apps to prevent **Man-in-the-Middle (MitM)** attacks by hardcoding or "pinning" a specific certificate or public key in the app. This ensures that the app only accepts connections to servers with that exact certificate, even if the device trusts other CA-signed certificates.

---

## Why Use Certificate Pinning?

Normally, HTTPS connections rely on the system's trusted Certificate Authorities (CAs). However, if an attacker can compromise or trick a CA (or install a custom one on a rooted device), they can intercept and decrypt traffic.

Pinning prevents this by explicitly trusting only a specific certificate or public key, rather than all the CAs in the device’s trust store.

#### Example: Implementing SSL Pinning in Android (Java)
```java
CertificateFactory cf = CertificateFactory.getInstance("X.509");
InputStream caInput = context.getResources().openRawResource(R.raw.server_cert);
Certificate ca = cf.generateCertificate(caInput);

KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
keyStore.load(null, null);
keyStore.setCertificateEntry("ca", ca);

TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
tmf.init(keyStore);

SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);

HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
``` 

## Bypassing SSL Pinning (For Testing)

If you're analyzing a mobile app that uses certificate pinning, tools like **Burp Suite** won't be able to intercept HTTPS traffic unless the pinning is bypassed. This can be done by:

- Using **Frida** to hook SSL functions and disable pinning.
- Recompiling the app and removing the pinning logic.
- Using **Magisk modules** like `TrustMeAlready` (for rooted devices).
- Tools like **Objection** or **apk-mitm** (for quick patches).