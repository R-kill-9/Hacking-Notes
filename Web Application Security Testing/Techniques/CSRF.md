**Cross-Site Request Forgery (CSRF)** is a web security vulnerability that allows an attacker to trick a user into performing actions on a web application where they are authenticated. This is achieved by exploiting the trust that a web application has in the user's browser. By using social engineering tactics, such as sending a link via email or embedding a malicious script on a website, an attacker can execute unauthorized commands on behalf of the user without their knowledge.

For a CSRF attack to occur, three essential conditions must be met:

1. **Relevant Action**: There must be an action within the application that the attacker aims to trigger. This could be a high-privilege action, like altering other users' permissions, or an action on user-specific data, such as changing the user’s own password.
    
2. **Cookie-Based Session Management**: The action requires issuing one or more HTTP requests, and the application uses session cookies exclusively to identify the user making the requests. There are no additional mechanisms in place for session tracking or user request validation.
    
3. **Predictable Request Parameters**: The requests needed to perform the action lack any parameters whose values the attacker cannot determine or guess. For instance, if an attacker needs to know the current password to change it, the function would not be vulnerable to CSRF.


---
## CSRF attack flow

A typical CSRF attack works by making the victim's browser send a request to the vulnerable application while the victim is authenticated.

The attacker does not need to know the victim's session cookie. The browser automatically includes the victim's cookies when requesting the target application.

A simplified flow is:

```
Attacker-controlled page
        |
        | malicious request
        v
Victim's browser
        |
        | includes session cookie
        v
Vulnerable application
        |
        v
Action performed as victim
```


---

## CSRF tokens
A CSRF token is a unique, secret, and unpredictable value that a web application generates and includes in forms or requests to protect against CSRF attacks.

### Common flaws in CSRF token validation
###### Validation of CSRF token depends on request method
Some applications correctly validate the token when the request uses the POST method but skip the validation when the GET method is used.

In this situation, the attacker can switch to the GET method to bypass the validation and deliver a CSRF attack:

```bash
# Original request
POST /my-account/change-email HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=VICTIM_SESSION

email=attacker@example.com&csrf=TOKEN
```

```bash
# Modified request
GET /my-account/change-email?email=attacker@example.com HTTP/2 Host: vulnerable-website.com 
Cookie: session=VICTIM_SESSION
```

Once the GET request has been confirmed to change the email, the request can be embedded into an HTML page hosted on the attacker's controlled server.

For example:

```html
<iframe src="https://vulnerable-website.com /my-account/change-email?email=adminfake%40normal-user.net"></iframe>
```

When the victim opens the exploit page, their browser requests the URL and automatically includes their session cookie. The vulnerable application therefore processes the email change as if the victim had performed the action themselves.

###### Validation of CSRF token depends on token being present

Some applications correctly validate the token when it is present but skip the validation if the token is omitted.

In this situation, the attacker can remove the entire parameter containing the token (not just its value) to bypass the validation and deliver a CSRF attack:

```bash
POST /email/change HTTP/1.1 Host: vulnerable-website.com Content-Type: application/x-www-form-urlencoded Content-Length: 25 Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm email=pwned@evil-user.net
```

##### CSRF token is not tied to the user session

Some applications do not validate that the token belongs to the same session as the user who is making the request. Instead, the application maintains a global pool of tokens that it has issued and accepts any token that appears in this pool.

In this situation, the attacker can log in to the application using their own account, obtain a valid token, and then feed that token to the victim user in their CSRF attack.

---

## Exploit delivery

Once the CSRF request has been confirmed, the attacker needs to make the victim's browser send it. 

For a GET-based CSRF, a simple iframe can trigger the request:

```html
<iframe src="https://vulnerable-website.com/my-account/change-email?email=attacker@example.com"></iframe>
```

For a POST-based CSRF, an auto-submitting HTML form can be used:

```html
<form action="https://vulnerable-website.com/my-account/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@example.com">
</form>

<script>
    document.forms[0].submit();
</script>
```

### Cookie restrictions

The browser may not always send the victim's session cookie with a cross-site request. The `SameSite` attribute can prevent CSRF depending on its configuration and the type of request.

```
Set-Cookie: session=abc123; SameSite=Strict
```

```
Set-Cookie: session=abc123; SameSite=Lax
```

```
Set-Cookie: session=abc123; SameSite=None; Secure
```

Therefore, when testing CSRF, verify that the victim's authentication cookie is actually included in the cross-site request. If it is not, the attack may fail even if the application lacks CSRF token validation.