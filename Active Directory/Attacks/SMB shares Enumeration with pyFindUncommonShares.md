[pyFindUncommonShares](https://github.com/p0dalirius/pyFindUncommonShares) is a Python tool created by Podalirius to enumerate uncommon SMB shares across large Windows Active Directory domains. It is the Python equivalent of PowerView’s `Invoke-ShareFinder.ps1`.

---

## Key Features

- Works with **low-privileged domain accounts**.
    
- Retrieves the list of computers automatically from LDAP.
    
- Can **ignore hidden shares** (ending with `$`) or print queues.
    
- Supports **multithreaded scanning** for speed.
    
- Exports results to **JSON, XLSX, or SQLite**.
    
- Filters results by **readable** or **writable** shares.
    
- Can check **user-specific access rights**.
    

## Installation

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

---

## Basic Usage
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

## Possible Troubleshooting

1. **ImportError: cannot import name** `init_ldap_session`
    
    - Cause: `wrappers.py` imports incorrectly from `sectools.windows.ldap`.
        
    - Fix: Change the import line in `wrappers.py` to:
    
```bash
from sectools.windows.ldap.ldap import init_ldap_session
```

2. `sectools>=1.5.1` **not found on PyPI**

- Cause: Only version 1.5.0 is available on PyPI.
    
- Fix: Install directly from GitHub:
```bash
pip install git+https://github.com/p0dalirius/sectools.git
```

3. **ModuleNotFoundError: No module named** `xlsxwriter`

- Cause: Missing dependency.
```bash
pip install xlsxwriter
```