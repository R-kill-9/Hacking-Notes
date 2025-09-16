This category refers to flaws in the design or implementation of authentication and access control mechanisms. If improperly implemented, it may allow attackers to impersonate users, bypass login mechanisms, or escalate privileges.

Common issues include:

- Insecure Direct Object References (IDOR)
- Hidden or debug endpoints bypassing authentication
- Weak or missing user role enforcement
- Anonymous access to backend APIs
- Storing credentials or secrets locally on the device
- Weak or unenforced password policies


---

## Bypassing Authentication via Debug Code

Some apps contain hidden debug functionalities left by developers for testing. These can allow bypassing login requirements.

#### Attack Process:

- Decompile the app using tools like jadx
- Identify hidden debug methods or flags (e.g., `debug=true`)
- Use the debug feature to bypass authentication and gain access

---

## Token Replay Attack

Applications using session tokens without expiration or proper validation are vulnerable to token reuse. Tokens captured by an attacker can be replayed to impersonate a user.

#### Attack Process:

- Capture a session token via MITM, local storage, or logs
- Replay the token in an API request to access the user's session

---

## Weak Biometric Authentication

Biometric systems (face, fingerprint) without liveness detection can be bypassed using static images or recordings.

#### Example:

An attacker uses a high-quality photograph of the victim to bypass facial recognition.

---

## Lack of Role-Based Access Control (RBAC)

Failure to implement proper access control mechanisms allows unauthorized users to perform privileged actions by manipulating API requests.

#### Attack Process:

- Send a normal request as a user
- Intercept the request using a proxy (e.g., Burp Suite)
- Modify parameters (e.g., `role=admin`, `user_id=2`) to access restricted data or functionality