**Session fixation** is a vulnerability in which an attacker causes a victim to authenticate using a session identifier that the attacker already knows. If the application does not regenerate the session ID after successful authentication, the attacker can reuse that identifier to access the victim's authenticated session.

Unlike session hijacking, where the attacker obtains an existing authenticated session, session fixation typically involves establishing or predicting the session identifier before the victim logs in.

The vulnerability occurs when an application accepts a session ID controlled or known by an attacker and preserves it across the authentication process.

---

## How session fixation works

A typical attack follows three stages:

1. **Session establishment:** The attacker obtains a valid session ID from the application or supplies one that the application accepts.
    
2. **Victim authentication:** The victim is tricked into using that session ID and logs in normally.
    
3. **Session reuse:** If the application retains the same session ID after authentication, the attacker can use the known identifier to access the victim's authenticated session.
    

The following sequence illustrates the vulnerability:

```
Attacker                  Web Application                 Victim
   |                            |                            |
   |--- Request session ------->|                            |
   |<-- SID=abc123 -------------|                            |
   |                            |                            |
   |--- Deliver SID=abc123 --------------------------------->|
   |                            |                            |
   |                            |<--- Login with SID --------|
   |                            |--- SID=abc123 authenticated|
   |                            |                            |
   |--- Reuse SID=abc123 ------>|                            |
   |<-- Authenticated session --|                            |
```

This attack only succeeds if the attacker can make the victim use the known session identifier, the application preserves that identifier after authentication, and the attacker can subsequently send requests using it.


---

## Identifying Session Fixation

During a penetration test, the main objective is to determine whether the application regenerates its session identifier when the authentication state changes.

### 1. Inspect the session cookie

Browse the application without logging in and inspect the response in Burp Suite. Look for session cookies such as `PHPSESSID`, `JSESSIONID`, `connect.sid`, or a custom session cookie.

Example HTTP response:

```
HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=7f3a91b2c4d5e6f8; Path=/; HttpOnly; SameSite=Lax
Content-Type: text/html
```

Record the session identifier issued before authentication. The cookie's name and value are application-specific; the example above is illustrative.

Check whether the application accepts an existing session ID supplied by the client or whether it always replaces client-supplied values with a newly generated identifier.

### 2. Compare session IDs before and after authentication

Log in using a test account and inspect the HTTP response to the authentication request in Burp Suite. Compare the session ID issued before login with the one used after successful authentication.

A secure implementation should regenerate the session ID when the user authenticates, preventing an attacker from reusing a previously known identifier to access the authenticated session.

If the session ID changes after login, this indicates that session regeneration is taking place. However, verify that the original session ID is invalidated or remains unauthenticated, since changing the identifier alone does not guarantee that the session is properly protected.

### 3. Verify whether the original session becomes authenticated

Using an authorized test account, compare the behavior of the original and post-login session identifiers.

For example, send a request to an authenticated endpoint:

```
GET /dashboard HTTP/1.1
Host: app.example.test
Cookie: PHPSESSID=7f3a91b2c4d5e6f8
```

If the original session ID grants access to the authenticated dashboard after login, the application may be vulnerable to session fixation.

If the original ID is invalidated or remains unauthenticated while the new ID grants access, that is the expected secure behavior.

---

## Exploiting Session Fixation

The following techniques illustrate how session fixation can be tested in an authorized lab. They should be performed with test accounts and sessions you control.

### 1. Attempt to set a known session ID

Some applications accept session IDs through cookies without checking whether the identifier was issued by the server. Others accept identifiers through URL parameters or other request fields.

For example, an application might accept this request:

```
GET / HTTP/1.1
Host: app.example.test
Cookie: PHPSESSID=attackercontrolled123
```

Check the response to determine whether the application accepts the supplied identifier or replaces it with a server-generated value.

Acceptance alone does not prove a vulnerability. The key question is whether the application binds authenticated state to that same identifier after login.

### 2. Test session persistence across authentication

If the application accepts a test session ID, record it and authenticate using that session in your own browser or test client.

In Burp Suite, compare the session cookie before and after submitting the login form. Then request a protected resource using the original identifier.

A vulnerable application may preserve the session identifier and associate it with the authenticated user:

```
GET /account HTTP/1.1
Host: app.example.test
Cookie: PHPSESSID=attackercontrolled123
```

If this request returns authenticated account information after the login operation, you have evidence that the session ID was not rotated appropriately.

For a valid finding, document the initial session ID, the authentication response, the post-login session state, and the protected endpoint response. Redact session tokens, passwords, and personal information in the report.

### 3. Test URL-based session identifiers

Legacy applications sometimes place session identifiers in URLs instead of cookies.

```
GET /login?SID=attackercontrolled123 HTTP/1.1
Host: app.example.test
```

Inspect whether the application honors the parameter and whether the identifier remains unchanged after authentication.

URL-based session identifiers are particularly risky because URLs can be recorded in browser history, server logs, analytics systems, and referrer headers. Prefer cookie-based session management and reject URL-based session tracking where possible.

---

## Advanced Testing Techniques

### Session fixation versus session hijacking

These vulnerabilities involve session identifiers but differ in the initial condition.

|Characteristic|Session fixation|Session hijacking|
|---|---|---|
|Initial condition|Attacker knows or influences the victim's session ID before authentication|Attacker obtains an existing session identifier|
|Main weakness|Session ID is not rotated appropriately during authentication|Session identifier is exposed, stolen, or otherwise compromised|
|Primary test|Compare session identifiers before and after login|Investigate token exposure and unauthorized reuse|
|Key mitigation|Regenerate the session ID after authentication and privilege changes|Protect session tokens and prevent their disclosure|

Both vulnerabilities can result in unauthorized access to an authenticated session.

### Test privilege changes and reauthentication

Session rotation should not be limited to the initial login. Examine transitions that change the security context, including privilege elevation, account switching, password changes, and reauthentication for sensitive operations.

For example, authenticate as a regular user and then perform an authorized role or privilege transition in the test environment. Determine whether the session identifier changes and whether the previous identifier can still access protected resources.

A session ID that remains valid after a significant privilege change can indicate insufficient session lifecycle management, even if the initial login correctly rotates the cookie.

### Cookie attributes and their limitations

Inspect the session cookie for security attributes:

```
Set-Cookie: SESSIONID=c9d2e4f6a8b0c1d3; Path=/; Secure; HttpOnly; SameSite=Lax
```

- `Secure` restricts cookie transmission to HTTPS.
    
- `HttpOnly` prevents JavaScript from reading the cookie through standard browser APIs.
    
- `SameSite` helps mitigate certain cross-site request forgery scenarios.
    

These attributes improve session security, but they do not replace session ID regeneration. An application can use all three attributes and still be vulnerable to session fixation if it preserves an attacker-known identifier after authentication.
