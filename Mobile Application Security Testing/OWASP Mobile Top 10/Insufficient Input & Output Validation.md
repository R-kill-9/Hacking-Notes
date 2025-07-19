This category covers flaws arising from improper validation, sanitization or encoding of user-supplied input or output data. These flaws may allow attackers to inject malicious data, manipulate the application’s behavior or exploit memory-based vulnerabilities.

Key issues include:

- Lack of input validation on user-supplied data
- Inadequate output encoding or sanitization
- Failure to apply context-specific validation (e.g., HTML vs SQL vs JSON)
- Absence of integrity checks on received data
- Weak secure coding practices (e.g., using unsafe parsing methods)


---

## SQL Injection via Search Functionalities

Occurs when the application passes user input directly into SQL queries without proper sanitization. Attackers can manipulate queries to access unauthorized data or modify the database.

#### Attack Process:

- Identify fields such as login or search inputs
- Inject payloads such as `' OR 1=1 --` into input fields
- Bypass filters or extract data using SQL injection

---

## XSS and CSRF in WebView or Browser Usage

Applications that use `WebView` to render untrusted content or load remote URLs are vulnerable to client-side attacks such as Cross-Site Scripting (XSS) or Cross-Site Request Forgery (CSRF).

#### Attack Process:

- Inject malicious JavaScript via URL parameters or stored content
- Exploit insecure WebView configurations to execute arbitrary scripts
- Perform unauthorized actions using CSRF if session tokens are stored or transmitted insecurely

---

## Remote Code Execution via File Upload

If an app allows file uploads without validating content type, size, or extension, an attacker may upload executable or script files that are later processed insecurely by the server or client.

#### Attack Process:

- Upload a crafted `.php`, `.exe`, or `.js` file
- Trigger execution via direct access or by forcing the server to process the file
- Gain remote execution or data access

---

## Buffer Overflow via User Input

A buffer overflow may occur when the application fails to verify the length or format of user input. For example, unvalidated biometric data or sensor input can trigger memory corruption.

#### Attack Process:

- Provide overly large or malformed input to app components
- Exploit memory mismanagement to crash the app or execute arbitrary code

---

## Directory Traversal via File Download

Some apps allow users to download files by specifying a path or filename. If not properly validated, attackers may request files outside the intended directory structure using path traversal sequences.

#### Attack Process:

- Identify file download parameters (e.g., `file=report.pdf`)
- Modify input to include `../` sequences (e.g., `../../etc/passwd`)    
- Access sensitive system or configuration files