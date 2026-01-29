**SMB** (Server Message Block) is a network file sharing protocol used by Windows-based systems to facilitate file and printer sharing, as well as communication between devices on a local network.


---


## SmbClient 
It is a network protocol tool that allows users to communicate with remote computers and servers to use their resources or share, open, and edit files.

- `-U` access as user.
- `-N` No password.
- `-L` This option allows you to look at what services are available on a server.
```bash
smbclient -U bob //10.129.42.253/users
# You can list resources without user with this command:
smbclient -N -L //10.129.117.14/
```

To **list the contents of a specific directory** inside a shared resource on the server:

1. Connect to the shared resource using `smbclient`.
2. Once inside, use the `ls` command to view the contents of the current directory.

```bash
smbclient //10.129.42.253/users -U bob
smb: \> ls
```

To download all content from a shared resource using `smbclient`, you can use the `mget *` command, which downloads all files in the current directory.

```bash
smb: \> mget *
```

To download all files and directories you need to execute these commands:

```bash
# Enable recursive download
smb: \> recurse ON
# Turn off interactive prompts for each file
smb: \> prompt OFF
# Download all files and folders
smb: \> mget *
```

---
## Smbmap
It is designed to enumerate and interact with shared files and another resources, providing information about their accessibility, permissions, and potential vulnerabilities.
- `-H`: Specifies the target IP address (replace "192.168.1.100" with the actual IP).
- `-u`: Specifies the username for authentication.
- `-p`: Specifies the password for authentication.
```bash
smbmap -H ip -u username -p password
```


---

## PsExec
**PsExec** is a tool from the **Sysinternals Suite** developed by Microsoft. It is used to execute processes or commands on remote systems without requiring manual installation of client software.

#### Key Features

- Execute commands remotely on Windows systems.
- Copy and execute binaries to remote machines.
- Open interactive remote command prompts.
- Run processes as SYSTEM or other users.
- Work over SMB protocol for communication.

#### Usage

| Option      | Description                                                                |
| ----------- | -------------------------------------------------------------------------- |
| `<target>`  | Specifies the target machine. Use `\\*` for all machines in a domain.      |
| `-u <user>` | Specifies the username for authentication (e.g., `-u Administrator`).      |
| `-p`        | Specifies the password for the given username.                             |
| `-s`        | Runs the command as the SYSTEM account.                                    |
| `-i`        | Starts an interactive session on the target.                               |
| `-d`        | Does not wait for the process to terminate. Useful for long-running tasks. |
| `-c`        | Copies the executable file to the target system before running it.         |
| `-h`        | Runs the command with elevated privileges on the target.                   |
| `-v`        | Verifies that the target binary is a valid image.                          |
```bash
python3 psexec.py <user>@<target_ip> 
```


---

## Enumeration using Nmap
**Nmap** scripts can be very useful for enumerating SMB information. They can be listed using `ls /usr/share/nmap/scripts | grep smb`.
- **smb-enum-shares**: Lists shared directories available on the SMB service and checks for anonymous access.
- **smb-enum-users**: Enumerates user accounts on the SMB server, revealing potential usernames.
- **smb-os-discovery**: Detects the operating system version and build of the target using SMB.
- **smb-security-mode**: Retrieves the SMB security settings, such as authentication requirements.
- **smb-vuln-ms17-010**: Checks if the target is vulnerable to MS17-010.
- **smb-protocols**: Detects and enumerates the SMB protocol versions (e.g., SMBv1, SMBv2, SMBv3) supported by the target, identifying outdated or insecure versions.

```bash
nmap --script <script_name> <target_ip>
```


---


## Enumeration using Metasploit
**Metasploit** offers several modules for enumerating SMB services on a target.

- **Identify SMB Services**: Use `smb_version` to identify the type and version of SMB running. This helps in selecting the right attack vector.
- **Enumerate Shares**: Use `smb_enumshares` to list shares and look for ones with sensitive data or weak permissions.
- **List Users**: Use `smb_enumusers` to gather usernames for potential brute force attacks or privilege escalation.
- **Check Anonymous Access**: Test for shares or access points that are open to the "anonymous" user.
- **Explore Active Sessions**: Use `smb_enum_sessions` to identify logged-in users, which can help in social engineering or session hijacking.
- **Credentials Brute Force Attack**: Use `smb_login` to perform brute force attack with username and password dictionaries.

```bash
use <module_name>
set RHOSTS <target IP>
run
```

---

## Eternal Blue
**Eternal Blue** is a critical vulnerability in the SMBv1 protocol  on Windows systems, specifically identified as **MS17-010** or **CVE-2017-0144**. This exploit allows attackers to execute remote code on unpatched systems, granting full access to compromised machines without needing authentication.
#### **Affected Systems**

- **Windows Server** versions:
    - **Windows Server 2003**
    - **Windows Server 2008 / 2008 R2**
    - **Windows Server 2012 / 2012 R2**
    - **Windows Server 2016** (unpatched)
    - **Windows Server 2019** (if SMBv1 is manually enabled and unpatched)
- **Windows OS Versions**:
    
    - **Windows XP**
    - **Windows Vista**
    - **Windows 7**
    - **Windows 8 / 8.1**
    - **Windows 10** (unpatched)
    
_Note_: Systems with SMBv1 disabled or patched against MS17-010 are generally protected from EternalBlue.

This nmap script allows you to know if the target machine is vulnerable to `Eternal Blue`.

```bash
nmap -p445 --script smb-vuln-ms17-010 <target_ip>
```

After executing the nmap command if the SMB service is vulnerable the associated CVE will be printed.

After validating the existance of the vulnerability, it can be exploited using `Metasploit`.

```bash
msfconsole
search eternalblue
use 0
```


---

## SMBv1 Anonymous connection

If **SMBv1** is enabled, the server is more likely to allow **anonymous connections** due to the lack of modern security controls in the protocol.

**Command to check for anonymous access**:

```bash
smbclient -L //<target_ip>/ 
# When the password is required type Anonymous
```