**Cross-Site Request Forgery (CSRF)** is a web security vulnerability that allows an attacker to trick a user into performing actions on a web application where they are authenticated. This is achieved by exploiting the trust that a web application has in the user's browser. By using social engineering tactics, such as sending a link via email or embedding a malicious script on a website, an attacker can execute unauthorized commands on behalf of the user without their knowledge.

For a CSRF attack to occur, three essential conditions must be met:

1. **Relevant Action**: There must be an action within the application that the attacker aims to trigger. This could be a high-privilege action, like altering other users' permissions, or an action on user-specific data, such as changing the user’s own password.
    
2. **Cookie-Based Session Management**: The action requires issuing one or more HTTP requests, and the application uses session cookies exclusively to identify the user making the requests. There are no additional mechanisms in place for session tracking or user request validation.
    
3. **Predictable Request Parameters**: The requests needed to perform the action lack any parameters whose values the attacker cannot determine or guess. For instance, if an attacker needs to know the current password to change it, the function would not be vulnerable to CSRF.

## CSRF tokens
A CSRF token is a unique, secret, and unpredictable value that a web application generates and includes in forms or requests to protect against CSRF attacks.

### Common flaws in CSRF token validation
###### Validation of CSRF token depends on request method
Some applications correctly validate the token when the request uses the POST method but skip the validation when the GET method is used.

In this situation, the attacker can switch to the GET method to bypass the validation and deliver a CSRF attack:

`GET /email/change?email=pwned@evil-user.net HTTP/1.1 Host: vulnerable-website.com Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm`

###### Validation of CSRF token depends on token being present

Some applications correctly validate the token when it is present but skip the validation if the token is omitted.

In this situation, the attacker can remove the entire parameter containing the token (not just its value) to bypass the validation and deliver a CSRF attack:

`POST /email/change HTTP/1.1 Host: vulnerable-website.com Content-Type: application/x-www-form-urlencoded Content-Length: 25 Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm email=pwned@evil-user.net`

##### CSRF token is not tied to the user session

Some applications do not validate that the token belongs to the same session as the user who is making the request. Instead, the application maintains a global pool of tokens that it has issued and accepts any token that appears in this pool.

In this situation, the attacker can log in to the application using their own account, obtain a valid token, and then feed that token to the victim user in their CSRF attack.