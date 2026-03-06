
## NetExec (Linux/Windows)
NetExec is a multipurpose network tool that can also scan SMB shares using the `--spider` option. It allows content-based searches for sensitive files remotely.

**Basic Usage:**

```bash
nxc smb 10.129.234.121 -u user -p 'pass!' --spider IT --content --pattern "passw"
```

**Example Output:**

- Host information and SMB configuration: version, signing, SMBv1 status.
    
- Successful login with given credentials.
    
- Spidering progress through target share (e.g., IT).
    
- Identified files containing the string `passw`.

---

## Snaffler
**Snaffler** is an Active Directory post-enumeration tool designed to locate **credentials, secrets, and sensitive files** stored in network shares.

It automates the discovery of high-value data by:

- Enumerating domain hosts
    
- Discovering shared folders (SMB shares)
    
- Identifying readable directories
    
- Searching for sensitive file types and keywords
    

### Basic Execution

Example command:

```bash
Snaffler.exe -s -d domain.local -o snaffler.log -v data
```

![](../../../Images/snaffler_output.png)

#### Parameters

|Option|Description|
|---|---|
|`-s`|Print results to console (stdout)|
|`-d`|Target Active Directory domain|
|`-o`|Output logfile|
|`-v`|Verbosity level|


### Output Interpretation

Snaffler uses **color classification**:

|Color|Meaning|
|---|---|
|Green|Accessible shares discovered|
|Black|Interesting but lower priority files|
|Red|High-value sensitive data|

Example findings:

- `.key`
    
- `.ppk`
    
- `.kdb`
    
- `.sqldump`
    
- `.mdf`
    
- `.keychain`
    
- `.psafe3`
    


---

## pyFindUncommonShares (Windows)
[pyFindUncommonShares](https://github.com/p0dalirius/pyFindUncommonShares) is a Python tool created by Podalirius to enumerate uncommon SMB shares across large Windows Active Directory domains. It is the Python equivalent of PowerView’s `Invoke-ShareFinder.ps1`.


### Installation

Clone the repository and install requirements:

```bash
git clone https://github.com/p0dalirius/pyFindUncommonShares.git
cd pyFindUncommonShares
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If `sectools>=1.5.1` is not available on PyPI, install directly from GitHub:
```bash
pip install git+https://github.com/p0dalirius/sectools.git
```

### Basic Usage
List all shares where the current user has **WRITE** access:
```bash
./FindUncommonShares.py -au user -ap 'Password123!' -ad DOMAIN --auth-dc-ip 192.168.1.71 --writable
```

Check access rights for the current user:
```bash
./FindUncommonShares.py -au user -ap 'Password123!' -ad DOMAIN --auth-dc-ip 192.168.1.71 --check-user-access
```

List all shares where the current user has **WRITE** access:
```bash
./FindUncommonShares.py -au user -ap 'Password123!' -ad DOMAIN --auth-dc-ip 192.168.1.71 --writable
```

Export results to Excel:
```bash
./FindUncommonShares.py -au user -ap 'Password123!' -ad DOMAIN --auth-dc-ip 192.168.1.71 --export-xlsx results.xlsx
```

Ignore hidden shares:
```bash
./FindUncommonShares.py -au user -ap 'Password123!' -ad DOMAIN --auth-dc-ip 192.168.1.71 --ignore-hidden-shares
```


---

## PowerHuntShares (Windows)

PowerHuntShares is a **PowerShell script** for enumerating SMB shares, their permissions, and files, generating **HTML and CSV reports** for easier review. It doesn’t require the host to be domain-joined.

**Basic Usage:**

```powershell
Invoke-HuntSMBShares -Threads 100 -OutputDirectory C:\Users\Public
```

**Workflow:**

1. Determine the domain of the current machine.
    
2. Enumerate computers in the domain.
    
3. Ping and check port 445 for SMB availability.
    
4. Enumerate shares and permissions.
    
5. Identify risky shares and high-value targets.
    
6. Output results in **HTML and CSV** for easy review.
    

---

## MANSPIDER (Linux)

MANSPIDER is a **Linux tool** for scanning SMB shares remotely, especially when no domain-joined machine is available. It is often run via **Docker** to avoid dependency issues.

**Basic Usage (Docker):**

```bash
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'user' -p 'pass!'
```

**Output:**

- Successful authentication as the provided user.
    
- Matching files saved in `/root/.manspider/loot`.
    
- Skips files larger than a specified size.
    
