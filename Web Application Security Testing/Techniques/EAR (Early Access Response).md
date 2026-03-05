**EAR** is a logic flaw in web applications where a **200 OK** HTTP response with content is sent **before** a **302 Redirect** response that should normally prevent access. This premature exposure allows attackers to access protected content or functionalities without proper authorization.


**Example**
```bash
Request: GET /protected-page HTTP/1.1
Host: example.com

Response #1: HTTP/1.1 200 OK
Content-Type: text/html
[...Sensitive HTML content here...]

Response #2: HTTP/1.1 302 Found
Location: /login
```
In this case, the sensitive content is sent **before** redirecting the user to login, exposing protected data.


--- 


## How to Detect EAR

1. **Intercept HTTP traffic** using tools like Burp Suite or any proxy.
2. Look for requests where you see a **200 OK** response followed by a **302 Redirect**.
3. Save and analyze the 200 response content for sensitive data.
4. Attempt direct access to the URL with a browser or curl to check if it requires authentication.