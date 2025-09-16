This vulnerability occurs when applications **mishandle credentials**, including weak storage, insecure transmission or weak authentication mechanisms. It may lead to **account takeover**, **unauthorized API access** or **data exposure**.


---

## Hardcoded Credentials

Developers sometimes embed API keys, tokens, or user credentials **directly in the source code**, which can be easily extracted by reverse engineers.

#### Attack Steps:

1. Download the `.apk` file from the device or a store.
2. Decompile using tools like **Jadx** or **APKTool**.
3. Search for hardcoded secrets.
4. Use the extracted credentials via tools like **Postman** or custom scripts to access backend services.



---


## Weak Password Policies

Allowing insecure passwords (e.g., short, predictable) without enforcing rate-limiting or account lockout mechanisms increases the risk of **credential stuffing** or **brute-force** attacks.

Accepting passwords like `123456`, `password`, or `admin` with no complexity requirements.

#### Attack Steps:

1. Prepare a list of leaked or common passwords.
2. Automate login attempts using hydra or Burp.
3. If rate-limiting or lockout is missing, eventually gain access to user accounts.


---


## Insecure Credential Storage

Storing sensitive data like passwords or tokens in **plaintext** on the device allows attackers to retrieve them via local access.

**Example:**

A social media app saves the user’s password in plaintext for “Remember Me” functionality.
```json
// /data/data/com.example.app/shared_prefs/user.xml
{
  "username": "alice",
  "password": "mypassword123"
}
```

#### Attack Steps:

1. Obtain access to the user's device (via physical access, malware, or backup).
2. Navigate to internal storage directories.
3. Extract plaintext credentials from files or `SharedPreferences`.

---

## Insecure OAuth Implementation

Using unsafe flows or configurations in OAuth, such as the **implicit grant flow**, exposes tokens to interception.

**Example:**

An e-commerce app uses **OAuth 2.0 implicit grant**, sending tokens over unencrypted HTTP.

#### Attack Steps:

1. Perform a **Man-in-the-Middle (MITM)** attack using tools like **Burp Suite** or **mitmproxy**.
2. Capture the token in HTTP traffic.
3. Replay the token to impersonate the user or access protected resources.



## Logging Sensitive Information

Apps that log credentials, tokens, or session data in system logs may unintentionally expose them to attackers or forensic tools.

#### Attack Steps:

1. Connect the target device using ADB.
2. Dump logs:
```bash
adb logcat > logs.txt
```
3. Search logs for sensitive keywords.
4. Extract and use the leaked credentials.