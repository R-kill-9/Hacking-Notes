Before starting a mobile application security assessment, it is essential to align expectations, scope, and technical constraints with the client. The following points should be discussed and agreed upon in advance:

---

## 1. Clarify the Scope (Android, iOS, Backend)

Define whether the assessment covers the Android app, iOS app, APIs/backend that interact with the app, or all components. This prevents misunderstandings and ensures proper coverage of the attack surface.

---

## 2. Provide Installable Files (.APK / .IPA)

Request the latest production or pre-production APK/IPA. This allows testing in conditions similar to what end users experience. Ideally, use a **non-obfuscated build** for more efficient reversing and analysis.

---

## 3. SSL Pinning Considerations

Clarify that:

- SSL pinning **may be bypassed** using dynamic instrumentation (e.g., Frida).
- If **bypass is not possible**, the client should provide a build **without SSL pinning** to allow traffic inspection (especially crucial for dynamic analysis and API testing).


---

## 4. Reverse Engineering Support

Reverse engineering will be attempted on the application binary. If strong obfuscation prevents meaningful analysis:

- Ask the client to share **partial or full source code** of the mobile app to aid static analysis.

- For iOS, source code is especially useful due to the challenges with iOS binary reversing.


---

## 5. Backend/API Documentation & Access

Request:

- API documentation (e.g., Swagger, Postman collection) if available.
- Authentication credentials (test users).
- Any required tokens or headers (e.g., API keys).  


---

## 6. Test Environment & Data Isolation

Confirm if there is a **dedicated testing environment** (e.g., staging server). This prevents disruption of production systems and allows more aggressive testing (e.g., fuzzing, account manipulation).

---

## 7. Jailbroken/Rooted Device Testing Consent

Inform the client that:

- Testing will involve **rooted Android** and/or **jailbroken iOS** devices to simulate advanced attacker scenarios.

- This may reveal security issues not visible on non-rooted devices (e.g., insecure storage, bypasses).    

---

## 9. Authentication Methods

Clarify:

- What authentication flows are in use (OAuth2, JWT, biometric, 2FA, etc.).
- If credentials or test accounts will be provided (with different roles if possible).

