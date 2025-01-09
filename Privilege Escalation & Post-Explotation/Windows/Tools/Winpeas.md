**WinPEAS** (Windows Privilege Escalation Awesome Script) is a tool used for enumerating privilege escalation vectors on Windows systems. It automates the process of identifying misconfigurations, vulnerabilities, and other opportunities for privilege escalation.


---

## Installation
 Download the latest release from the [PEASS-ng GitHub repository](https://github.com/carlospolop/PEASS-ng):

```bash
curl -LO https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
```


## Usage

#### Basic Execution
Run WinPEAS directly:

```bash
.\winPEASx64.exe
```

#### Save output to a file 

To log results for later analysis:

```bash
.\winPEASx64.exe > winpeas_output.txt
```