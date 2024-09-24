From a cybersecurity perspective, cookies are often valuable targets for attackers because they contain data related to user sessions, authentication, preferences, or tracking information. Below are the main ways cookies can be exploited offensively:
# Session Hijacking

- Cookies often store **session identifiers** (e.g., `PHPSESSID`), which link a user's browser to their authenticated session on the server. If an attacker can steal this cookie, they can impersonate the user without needing their login credentials.
- Common ways attackers steal session cookies:
    - **XSS (Cross-Site Scripting)**: If an attacker injects malicious JavaScript into a vulnerable web application, they can capture cookies that are not protected by the **HttpOnly** flag.
    - **Network Sniffing**: If cookies are transmitted over HTTP instead of HTTPS, attackers can intercept them by eavesdropping on unencrypted network traffic.

# HttpOnly Flag Not Set
When the **HttpOnly** flag is not set on a cookie, it means that the cookie is accessible from client-side JavaScript. This can be a security risk because an attacker who successfully executes a **Cross-Site Scripting (XSS)** attack could steal this session cookie.

By setting the **HttpOnly** flag, security is enhanced, as it restricts access to the cookie from client-side code, allowing only the server to access it. This reduces the risk of client-side attacks such as XSS compromising sensitive session data.

# Cross-Site Request Forgery (CSRF)

- In a **CSRF** attack, an attacker tricks a user into submitting malicious requests on a site where the user is authenticated. Cookies containing session data are automatically included with the request by the browser. If a web application does not validate the origin of requests, the attacker can perform actions on behalf of the victim.