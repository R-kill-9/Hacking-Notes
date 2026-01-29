WMI is Microsoft’s implementation of the **Common Information Model (CIM)** and an extension of **Web-Based Enterprise Management (WBEM)**. It provides **read and write access to nearly all system settings** on Windows PCs and servers. This makes WMI a critical tool for administration, monitoring, and remote maintenance.


---

## Footprinting WMI

**Communication Ports:**

- TCP 135 (initial RPC/WMI handshake)
    
- Random high ports after session establishment
    

**Tools for WMI Enumeration & Execution:**

- `wmic.exe` (built-in Windows tool)
    
- PowerShell cmdlets: `Get-WmiObject`, `Get-CimInstance`
    
- Impacket: `wmiexec.py` (Python tool for remote command execution via WMI)
    

**Sample Impacket Command – Hostname Retrieval:**

```bash
impacket-wmiexec <user>:"<password>"@<target_ip> "<hostname>"
```

**Sample Output:**

```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] SMBv3.0 dialect used
ILF-SQL-01
```

---

## Remote Command Execution Using WMI

**PowerShell Example – Query Processes on Remote Host:**

```powershell
Get-WmiObject -Class Win32_Process -ComputerName TARGET -Credential (Get-Credential)
```

**PowerShell Example – Start Process Remotely:**

```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "notepad.exe" -ComputerName TARGET -Credential (Get-Credential)
```

**WMIC Example – Query OS Version:**

```cmd
wmic /node:TARGET /user:USERNAME /password:PASSWORD os get Caption, Version, BuildNumber
```

**Enumerate Services Remotely:**

```cmd
wmic /node:TARGET /user:USERNAME /password:PASSWORD service list brief
```
