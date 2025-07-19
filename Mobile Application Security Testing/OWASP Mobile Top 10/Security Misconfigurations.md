This category includes insecure default settings, improperly configured permissions, exposed sensitive resources or public access to endpoints that should be protected. Misconfigurations create exploitable weaknesses that attackers can discover and leverage to compromise data or systems.

---

## Common Issues

- Misconfigured Android/iOS permissions
- Unrestricted access to sensitive files or directories
- Use of weak or default credentials
- Improper exposure of internal API endpoints
- Insecure third-party service integration

---

## Misconfigured Permissions

Applications may request excessive permissions or incorrectly expose components such as Activities, Broadcast Receivers or Services. These misconfigurations can allow other apps to access or trigger unintended behavior.

### Attack Process:

- Analyze `AndroidManifest.xml` or iOS Info.plist
- Identify exported components (`exported=true`, no permission checks)
- Use tools like Drozer to interact with exported components and extract sensitive data

---

## Unrestricted Access to Sensitive Files

Sensitive configuration or runtime files (e.g., logs, tokens, databases) may be stored in insecure locations with world-readable or world-writable permissions. This allows attackers or other apps on the device to read or modify critical data.

### Attack Process:

- Inspect `/sdcard/`, shared_prefs or temp directories
- Identify readable files not properly secured
- Extract and analyze contents for secrets or sensitive information

---

## Weak Default Configuration

Apps or backend systems may use weak or default settings, such as hardcoded credentials (`admin:admin`), unencrypted channels, or verbose error messages. This increases the risk of unauthorized access and exploitation.


### Attack Process:

- Identify default credentials or open ports
- Use automated tools to test for default logins
- Gain control over the connected device or system

---

## Improper API Endpoint Exposure

Applications may expose internal or administrative API endpoints to the public or mobile app clients without authentication or access control. These endpoints are often meant only for internal use.

### Attack Process:

- Monitor API traffic using Burp Suite or MITM proxy
- Discover undocumented endpoints not linked in the UI
- Attempt direct access and observe server behavior
- Execute unauthorized actions such as data extraction or configuration changes