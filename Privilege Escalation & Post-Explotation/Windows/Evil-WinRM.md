**Evil-WinRM** is a popular open-source tool used in penetration testing to interact remotely with Windows machines. It is a client for **Windows Remote Management (WinRM)**, specifically designed to allow security professionals to access PowerShell consoles and execute commands remotely on Windows systems.

## Key Features

1. **Remote Access with PowerShell**:
    
    - Evil-WinRM allows remote connection to Windows systems and provides an interactive PowerShell shell. This means an attacker can execute commands and scripts directly on the compromised host.
2. **Authentication**:
    
    - It supports basic and NTLM authentication for accessing the target machine. You need a valid username and password, or an NTLM hash, to authenticate.
3. **File Upload and Download**:
    
    - Evil-WinRM facilitates transferring files to and from the remote system. This is useful for uploading tools or scripts needed during exploitation, or for exfiltrating information from the compromised machine.
## Example Usage

To connect to a Windows machine using `Evil-WinRM`, you would use a command like:
```bash
evil-winrm -i <TARGET_IP> -u <USERNAME> -p <PASSWORD>
```
Where:

- **`-i`**: Specifies the IP address of the target.
- **`-u`**: Specifies the username to use.
- **`-p`**: Specifies the password.

You can also use an NTLM hash instead of a password:
```bash
evil-winrm -i 10.10.10.10 -u administrator -H <NTLM_HASH>
```
### Requirements

- **WinRM Enabled**: The target machine must have the WinRM service enabled and configured to accept remote connections. In many Windows Server installations, this is enabled by default, but it is often disabled in more secure environments.
- **Credentials**: You need valid credentials (username and password or hash) to authenticate on the system.