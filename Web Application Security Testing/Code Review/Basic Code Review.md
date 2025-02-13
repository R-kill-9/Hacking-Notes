## **Reviewing Credentials or Sensitive Information**

Ensure that sensitive data like passwords, API keys, and tokens are not exposed inappropriately or hardcoded in the code.

 **Keywords for searching Hardcoded Secrets:**

1. **`password`** –> Look for hardcoded passwords in the code.
2. **`apikey`**, **`api_key`**, **`apiKey`** –> To identify exposed API keys.
3. **`secret`**, **`clientSecret`**, **`client_secret`** –> To find hardcoded secrets or tokens.
4. **`token`**, **`access_token`**, **`refresh_token`** –> Used for OAuth tokens or other sensitive access keys.
5. **`auth`**, **`authorization`** –> Could indicate hardcoded authorization credentials.
6. **`credentials`** –> Often used in context with sensitive information.
7. **`db_password`**, **`db_user`**, **`db_host`** –> Database credentials.
8. **`private_key`**, **`privatekey`** –> For hardcoded private keys.


## **Reviewing Configuration Files**

Configuration files often contain sensitive data and settings that can pose security risks if exposed or misconfigured.

**Interesting files to review**

- `.env`
- `SpringSecurityConfig`
- `application.properties`
- `application.yml`
- `config.json`
- `config.yml`
- `settings.json`
- `web.config`
- `app.config`
- `docker-compose.yml`
- `Dockerfile`
- `nginx.conf`
- `apache.conf`
- `.htaccess`
- `cloud-config.yml`
- `database.yml`
- `config.toml`


### **CORS (Cross-Origin Resource Sharing)**
CORS defines which domains can access resources on your server. Ensure it's properly configured to only allow trusted origins to interact with your server.

Review CORS headers such as `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers` to ensure they do not allow unwanted access. Avoid setting `Access-Control-Allow-Origin` to `*` (wildcard), as it could allow any domain to access your server's resources.


## **Cookies**
Ensure that cookies are securely configured with the `HttpOnly`, `Secure`, and `SameSite` attributes. These attributes protect the cookie from unauthorized access and prevent certain types of attacks like XSS and CSRF.

```java
sessionCookie.setHttpOnly(false);  sessionCookie.setSecure(false);
sessionCookie.sameSite(false);
```

## **Session Fixation**
If the application does not change the session identifier after a user logs in, it is susceptible to session fixation attacks. This occurs when an attacker sets or predicts a session ID before the user logs in and then uses that session ID to hijack the user's session after they have authenticated.

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                .sessionFixation().none()  // Improper configuration - Disables session fixation protection
            .and()
            .authorizeRequests()
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated();
    }
```

**Recommended solution:**

Ensure session fixation protection is enabled, and that the session ID is changed after successful authentication. Use `sessionFixation().migrateSession()` to protect against session fixation.

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .sessionManagement()
            .sessionFixation().migrateSession()  // Correct configuration - Changes the session ID after authentication
        .and()
        .authorizeRequests()
            .antMatchers("/login").permitAll()
            .anyRequest().authenticated();
}
```

