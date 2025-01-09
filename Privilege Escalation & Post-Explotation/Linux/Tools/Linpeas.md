**LinPEAS** (Linux Privilege Escalation Awesome Script) is a powerful enumeration script designed to identify potential privilege escalation vectors in Linux systems. It automates the process of discovering vulnerabilities, misconfigurations, and sensitive information that can be exploited for privilege escalation.

---

## Downloading LinPEAS

You can download LinPEAS from the [PEASS-ng GitHub repository](https://github.com/carlospolop/PEASS-ng).  
- Clone the repository:
```bash
git clone https://github.com/carlospolop/PEASS-ng.git
cd PEASS-ng/linPEAS
```

- Download the script using `wget` or `curl`:
```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
```

## Running LinPEAS

To run LinPEAS, execute the script on the target system. Ensure it has executable permissions:

```bash
./linpeas.sh
```

#### Common Usage Options

- **Run with verbose output**:

```bash
./linpeas.sh -v 
```

- **Save results to a file**:  
Redirect the output to a file for easier analysis:

```bash
./linpeas.sh > linpeas_output.txt
```