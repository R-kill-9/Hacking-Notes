**[PrivEscCheck](https://github.com/itm4n/PrivescCheck)** is a Python script designed to automate the enumeration of privilege escalation vectors on Linux systems. It identifies misconfigurations, vulnerabilities, and other issues that can lead to privilege escalation.

## Installation

Download the script from the [GitHub repository](https://github.com/itm4n/PrivescCheck):

```bash
git clone https://github.com/itm4n/PrivescCheck.git
cd PrivescCheck
```

## Usage

1. **Navigate to the Directory**:  
Open PowerShell and navigate to the folder where `privesccheck.py` is located.

2. **Run the Script**:
```powershell
# Basic checks only
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
# Extended checks + human-readable reports
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
```