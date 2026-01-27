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


---

## WinRM Login Using a Certificate (PFX)

If WinRM is exposed over **HTTPS (port 5986)**, a decrypted **PFX** can be used for authentication.

1. **Extract key and certificate**

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out cert.pem
```

2. **Login with Evil‑WinRM (SSL)**

```bash
evil-winrm -i <TARGET_IP> -c cert.pem -k key.pem -S
```

