This category refers to the improper handling and protection of sensitive data stored on the device. Applications that store personal, authentication or financial information insecurely are vulnerable to local attacks, especially on rooted or jailbroken devices.

---

## Common Issues

- Storing sensitive data in plaintext on disk
- Lack of encryption on local databases or shared preferences
- Misconfigured backup settings allowing unencrypted backups
- Caching of confidential information in temporary or unprotected files
- Writing sensitive information to log files

---

## Storing Sensitive Data in Plaintext

Applications may store tokens, passwords, PII or other sensitive data directly in plaintext files or preferences, making them easily accessible to attackers with physical or root access to the device.


#### Attack Process:

- Access local storage or shared_prefs directories    
- Open XML, SQLite, or JSON files
- Extract unencrypted values

---

## Database Files Accessible Without Encryption

Local databases used by apps (e.g., SQLite) may store sensitive records without using encryption mechanisms. If these files are not secured with encryption or access control, they are vulnerable.

#### Attack Process:

- Access the app's sandbox or use file system access tools
- Locate `.db` or `.sqlite` files
- Extract and browse table data for sensitive entries    

---

## Insecure Backup Mechanism

If the application allows system-level backups (`android:allowBackup="true"` on Android), its data may be included in cloud or local backups without proper encryption.

### Attack Process:

- Analyze app manifest to verify backup permissions    
- Trigger device backup process
- Extract and inspect the backup archive

---

## Caching Sensitive Data in Temporary Files

Some apps cache user information (such as profile data, tokens, or content) in temp files, images or logs. If these files are not purged or secured, attackers may retrieve confidential data.

#### Attack Process:

- Inspect app cache or temp directories
- Identify leftover user-specific data
- Retrieve information not intended to persist    

---

## Sensitive Data in Logs

Applications that write sensitive content (e.g., usernames, tokens, coordinates) to system or application logs expose it to other apps or forensic tools, especially on rooted devices.

#### Attack Process:

- Use `adb logcat` or similar tools to capture logs
- Identify sensitive strings such as authentication headers
- Reuse exposed information for impersonation or privilege escalation