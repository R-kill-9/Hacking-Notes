Security headers are essential HTTP response headers that help protect web applications from common threats like **Cross-Site Scripting (XSS), Clickjacking, data leaks, and insecure communication**. Improper configuration or missing security headers can introduce significant vulnerabilities, making their review and proper implementation a critical aspect of web security.

## Obtain Security Headers
Use `curl` or a browser extension to check for security headers.
```bash
curl -I http://example.com
```

## Important Headers 

#### Content Security Policy (CSP)

The **Content Security Policy (CSP)** header is a mechanism that helps prevent **XSS (Cross-Site Scripting)** and **data injection attacks** by restricting the sources from which content (scripts, images, styles, fonts) can be loaded. This header allows developers to explicitly define which sources are trusted, blocking malicious scripts from executing even if an attacker injects them into a web page.

- Common Directives:
    - `default-src 'self'` → Only allow content from the same origin.
    - `script-src 'self' https://trustedscripts.com` → Only allow scripts from the same origin and a trusted domain.
    - `object-src 'none'` → Blocks loading of plugins (Flash, Java, etc.).
    - `img-src 'self' data:` → Allows images from the same origin and inline data URLs.

```bash
Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.com
```

#### X-Frame-Options

The **X-Frame-Options** header protects against **clickjacking attacks**, where an attacker tricks a user into clicking a maliciously hidden button or link within an iframe. This attack is commonly used to steal credentials or perform unintended actions on behalf of the user.

- Values:
    - `DENY` → Prevents the page from being displayed in any iframe.
    - `SAMEORIGIN` → Allows embedding only within the same origin.
    - `ALLOW-FROM https://example.com` → (Deprecated) Allows embedding from a specific domain.

```bash
X-Frame-Options: SAMEORIGIN
```

#### HTTP Strict Transport Security (HSTS)

The **HTTP Strict Transport Security (HSTS)** header enforces the use of **HTTPS**, protecting users from **man-in-the-middle (MITM) attacks** and **protocol downgrade attacks**.

- Behavior: 
    - Ensures that the browser automatically upgrades all HTTP requests to HTTPS.
    - Prevents users from accepting invalid SSL certificates.
    - Can apply to subdomains using `includeSubDomains`.
- Values:
	- `max-age=31536000` → Enforces HTTPS for one year.
	- `includeSubDomains` → Ensures all subdomains also enforce HTTPS.
	- `preload` → Allows preloading in browsers that support HSTS preloading.
```bash
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

#### X-Content-Type-Options

The **X-Content-Type-Options** header prevents **MIME-sniffing** attacks, where a browser attempts to determine the content type of a response even if the server has specified a `Content-Type`. Attackers can exploit this behavior to execute **malicious scripts** by disguising them as a different file type.

```bash
X-Content-Type-Options: nosniff
```

Setting it to `nosniff` forces the browser to adhere strictly to the declared `Content-Type`.

#### X-XSS-Protection

The **X-XSS-Protection** header enables the **built-in XSS filters** in modern browsers. It blocks malicious scripts that attempt to inject code into the page.

- Values:
    - `0` → Disables the XSS filter.
    - `1` → Enables the filter but allows rendering of the page.
    - `1; mode=block` → Blocks the page if an XSS attack is detected.

```bash
X-XSS-Protection: 1; mode=block
```

#### Referrer-Policy

The **Referrer-Policy** header controls how much referrer information is included in HTTP requests when users navigate between pages. This is important for **protecting user privacy** and **reducing information leakage** to third parties.

- Common Policies:
    - `no-referrer` → No referrer information is sent.
    - `no-referrer-when-downgrade` → Referrer is sent only for HTTPS → HTTPS requests.
    - `same-origin` → Referrer is sent only when navigating within the same origin.
    - `strict-origin` → Only the origin is sent when navigating to different sites.
```bash
Referrer-Policy: no-referrer-when-downgrade
```


#### Cache-Control

The **Cache-Control** header controls how responses are cached by browsers and proxies. This is critical for **preventing sensitive information from being stored in caches**, especially for authentication pages.

- Values:
	- `no-store` → Prevents storing any part of the response.
	- `no-cache` → Forces revalidation before using a cached response.
	- `must-revalidate` → Requires checking for a fresh version before using a cached copy.
```bash
Cache-Control: no-store, no-cache, must-revalidate
```

#### Cross-Origin Resource Sharing (CORS)

The **Cross-Origin Resource Sharing (CORS)** header defines which external domains are allowed to make requests to a web server. By default, **browsers block cross-origin requests** due to the **Same-Origin Policy (SOP)**. CORS enables controlled access while **preventing unauthorized cross-origin attacks**.

- Common Directives:
    - `Access-Control-Allow-Origin: *` → Allows requests from any origin (unsafe).
    - `Access-Control-Allow-Origin: https://example.com` → Allows only from a specific domain.
    - `Access-Control-Allow-Methods: GET, POST` → Specifies allowed HTTP methods.
    - `Access-Control-Allow-Headers: Content-Type, Authorization` → Specifies allowed headers.

```bash
Access-Control-Allow-Origin: https://trustedsite.com
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
```

#### Well configured headers example
```bash
HTTP/1.1 200 OK
Date: Sun, 24 Sep 2024 12:00:00 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.com
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer-when-downgrade
Permissions-Policy: geolocation=(self), microphone=()
Cache-Control: no-store
```