**SMB Relay** is a type of attack that targets the Server Message Block (SMB) protocol used primarily for providing shared access to files, printers, and serial ports in a network.

The attack involves intercepting and relaying SMB authentication attempts to another SMB server, allowing an attacker to gain unauthorized access or execute commands with the victim's credentials.

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

## Attack Process

1. **Configuring Responder**:

- Modify the `Responder.conf` configuration file to enable or disable specific protocols. For SMB relay, ensure that SMB and HTTP are set to `On` and that `HTTP Server` is also enabled.
```bash
sudo nano /etc/responder/Responder.conf
```
- Responder is a tool used to capture SMB/NTLM authentication attempts from victims. It works by spoofing services like SMB, DNS, and HTTP to trick devices into sending authentication requests to the attacker.

```bash
responder -I eth0
```

2. **Cracking hashes**:
- After some time different user hashes would be captured by the Responder. All this hashes can be cracked using tools as *John* or *Hashcat* before executing the relay. 

3. **Setting Up SMB Relay with Impacket**:
- Create a `targets.txt` file that contains the IP addresses of the target servers you want to relay the credentials to.
- Use Impacket's **ntlmrelayx.py** script to relay the captured credentials to another target server.
```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support
```
4. **Gaining access**:
Perform post-authentication actions:

- Dump sensitive information (e.g., SAM database, LSASS memory).
- Execute commands remotely.
- Create a reverse shell.
```bash
ntlmrelayx.py -tf targets.txt --dump
ntlmrelayx.py -tf targets.txt -c "whoami"
```

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
