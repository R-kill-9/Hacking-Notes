**SharpHound** is the official data collector for BloodHound. It enumerates Active Directory environments to gather information about users, groups, computers, sessions, ACLs, and trusts.


---


## Usage

- `-c, --collectionmethods`: Specify which collection methods to run.
    
- `-d, --domain`: Define the domain to enumerate.
    
- `--searchforest`: Expand enumeration to the entire forest.
    
- `--outputdirectory`: Directory where results are stored.
    
- `--zipfilename`: Name of the ZIP file containing results.
    
- `--nozip`: Disable ZIP compression.
    
- `--zippassword`: Protect the ZIP file with a password.
    
- `--randomfilenames`: Randomize output file names.
    
- `--threads`: Control number of concurrent threads (default 50).
    
- `--throttle` and `--jitter`: Add delays to reduce detection risk.
    
- `--stealth`: Prefer DCOnly collection for stealthier operation.

Collect all data and output to a ZIP file:
```bash
SharpHound.exe -c All --zipfilename data.zip
```

Collect only domain trusts:
```bash
SharpHound.exe -c Trusts --outputdirectory C:\Users\Public\loot
```

Run with stealth mode:
```bash
SharpHound.exe -c DCOnly --stealth
```

