This vulnerability refers to flaws in how the application transmits data over networks. It includes use of insecure channels, weak cryptographic configurations, improper certificate handling and the leakage of sensitive data during transmission.

Common issues:

- Use of plaintext (unencrypted) communication
- Lack of proper certificate validation or pinning
- Outdated or weak TLS configurations
- Transmission of sensitive data over push notifications
- Absence of end-to-end encryption (E2EE)
- Leakage of credentials or MFA tokens via unprotected channels

---

## MITM on Unencrypted Traffic

The application transmits sensitive information (e.g., credentials, tokens, user data) using HTTP instead of HTTPS, making it vulnerable to **Man-In-The-Middle (MITM)** attacks.

#### Attack Process:

- Intercept traffic using a proxy (e.g., Burp Suite)    
- Read or modify transmitted data
- Capture sensitive information including login credentials    

---

## Exploiting Weak TLS Configuration

The application uses HTTPS but relies on outdated TLS versions (such as TLS 1.0 or 1.1), which are vulnerable to known cryptographic attacks (e.g., POODLE, BEAST).

#### Attack Process:

- Force downgrade to weak TLS version
- Exploit protocol vulnerabilities to decrypt or tamper with traffic    

---

## Certificate Pinning Bypass

An application implements SSL certificate pinning but does so incorrectly or incompletely. This allows attackers to bypass the pinning using techniques like Frida instrumentation or SSL unpinning modules.

#### Attack Process:

- Use dynamic instrumentation tools to hook SSL-related methods    
- Bypass certificate validation
- Intercept and modify HTTPS traffic    

---

## Sensitive Data Leakage via Push Notifications

Applications may leak sensitive data (e.g., OTPs, account details) in push notification payloads, which are visible on lock screens and routed through third-party services (e.g., APNs, FCM).

#### Attack Process:

- Gain access to the victim’s device or lock screen
- View confidential information without needing to unlock the app
- Potentially intercept push data via service compromise    

---

## Lack of End-to-End Encryption

Data is encrypted in transit using TLS but not protected end-to-end. Intermediate services (e.g., proxies, backend APIs) can access unencrypted payloads.

#### Attack Process:

- Intercept or compromise backend infrastructure
- Access sensitive content as it is decrypted server-sid    
- Target applications relying solely on TLS without app-layer encryption