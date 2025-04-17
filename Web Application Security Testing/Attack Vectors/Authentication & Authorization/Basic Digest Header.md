**HTTP Digest Authentication** is a protocol that secures the login process by hashing credentials before sending them over the network. Instead of sending the username and password in plain text, it uses a challenge-response mechanism with a **nonce** (a unique, random value) to create a hash. The server verifies this hash to allow or deny access.

The credentials are hashed using an algorithm like MD5, combining elements such as the username, password, nonce, and request URI. This makes it harder for attackers to steal credentials just by intercepting traffic.


--- 


## Recognize Digest Authentication in a Request

When a server uses Digest Authentication, it challenges the client by sending a **401 Unauthorized** response that includes a **WWW-Authenticate** header. This header will indicate `Digest` authentication and include parameters such as `realm`, `nonce`, and `qop`.

```java
HTTP/1.1 401 Unauthorized
Date: Tue, 11 Mar 2025 19:13:52 GMT
Server: Apache/2.4.7 (Ubuntu)
WWW-Authenticate: Digest realm="private", nonce="random123", qop="auth", stale=false
Content-Length: 458
Connection: close
Content-Type: text/html; charset=iso-8859-1
```

## How to Attack HTTP Digest Authentication

Even though Digest Authentication adds security, it’s still vulnerable to brute force attacks if the password is weak. Hydra can be used to automate these attacks:

```bash
hydra -l <user> -P <wordlist> <target_ip> http-get -m /<directory>/ 
```