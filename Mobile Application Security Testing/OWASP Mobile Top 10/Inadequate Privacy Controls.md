This category addresses violations of user privacy due to improper handling, overcollection or insecure storage and transmission of personal data. It includes access to sensitive information without proper authorization or user consent, excessive logging and insecure data exposure.

Common issues:

- Storage of sensitive data without encryption    
- Lack of runtime permission enforcement
- Overcollection of personally identifiable information (PII)
- Misconfigured file or database storage
- Logging of private data in plaintext

---

## Unauthorized Access to Location Data

Applications request and access GPS or background location data without clear user consent or beyond their functional purpose.

#### Attack Process:

- Reverse engineer the app to identify location-related API    
- Interact with the app to verify continuous location access
- Analyze behavior that does not align with app function (e.g., games requesting background location)

---

## Unnecessary Access to Contacts

The app requests permission to access the contact list even when it is not required for the app’s core functionality, violating the principle of data minimization.

#### Attack Process:

- Install and run the app
- Use tools like Frida or objection to monitor access to contacts
- Identify overprivileged requests or unnecessary API call    

---

## Logging of Sensitive Information

Sensitive user data such as usernames, passwords, access tokens, or location coordinates are written to logs, which can be accessed by attackers via local device compromise or debugging tools.

#### Attack Process:

- Access the device or emulator
- Use `adb logcat` to retrieve logs
- Search for sensitive fields such as authentication headers or user credentials    

---

## Excessive Data Collection

The app collects more user data than is necessary for its operation, often including IMEI, installed apps list, clipboard contents or other device-level identifiers.

#### Attack Process:

- Monitor network traffic to identify outgoing telemetry
- Review app permissions and runtime behavior
- Analyze SDKs and native libraries bundled with the app    

---

## Exposing Sensitive Files via Misconfigured File Storage

Sensitive files (e.g., images, logs, tokens) are stored in world-readable locations such as public external storage (`/sdcard/`) or unprotected `shared_prefs`, making them accessible to other apps or attackers with filesystem access.

#### Attack Process:

- Access app storage directories
- Identify exported files or misconfigured `FileProvider` components    
- Extract and analyze file contents for sensitive data