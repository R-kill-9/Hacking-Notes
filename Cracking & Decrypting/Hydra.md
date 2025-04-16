**Hydra** supports a wide range of protocols, including SMB, HTTP, FTP, SMTP, Telnet, SSH, and many others. It works by sending multiple login attempts to the target system using a wordlist or custom dictionary file that contains potential usernames and passwords. Hydra then systematically tries each combination until it finds a successful login or exhausts all possibilities.

```bash
hydra -l <username> -P <password_list_path> <service>://<IP_or_domain_name> 
```

## Using hydra in a web login page
It can be useful intercept the petition with burp for extract the different fields. 

| Option                                            | Description                                                                         |
| ------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **`-l <username>`**                               | Specify the username (e.g., admin). Use `-L <file>` for a username list.            |
| **`-P <password_list>`**                          | Provide the path to the password list.                                              |
| **`-f`**                                          | Stop after the first successful attempt.                                            |
| **`<target_IP_or_URL>`**                          | Target IP address or domain name.                                                   |
| **`-s`**                                          | Specifies a certain port.                                                           |
| **`/path_to_login_form`**                         | The URI path of the login form (e.g., `/login.php`).                                |
| **`username_field=^USER^&password_field=^PASS^`** | Replace `username_field` and `password_field` with the actual form parameter names. |
| **`error_message`**                               | The response text shown when login fails (e.g., "Invalid username or password").    |
| **`http-post-form`**                              | Specifies the HTTP method and login form details.                                   |


```bash
hydra -t 64 -l <username> -P <password_list> -f http-post-form "http://<target-ip-or-url>/<path_to_login_form>:<username_field>=^USER^&<password_field>=^PASS^:<error_message>"
```
