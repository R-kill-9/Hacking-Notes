## PowerShell Location
You’ll typically find the main `powershell.exe` binary here:
```powershell
C:\Windows\System32\WindowsPowerShell
```


---


## Execution Policy Bypass

Windows uses _execution policies_ to restrict script execution. Attackers or pentesters often bypass these restrictions.

#### Check If PowerShell Is 64-bit

```powershell
[Environment]::Is64BitProcess
```
Returns `True` if the current process is 64-bit. Useful when dealing with payloads or DLLs that require specific architectures.

#### Bypass Execution Policy
```powershell
powershell.exe -ExecutionPolicy Bypass cmd.exe
```

Runs a new `cmd.exe` shell using PowerShell with the policy bypassed.

Set Execution Policy to Unrestricted
```powershell
powershell.exe -ExecutionPolicy Unrestricted cmd.exe
```
Opens `cmd.exe` through PowerShell with full script execution permissions. Risky on production systems.


---

## Process Enumeration

Useful for situational awareness or identifying target processes.

#### List All Processes
```powershell
Get-Process | Sort-Object Unique | Select-Object ProcessName, Id
```

Displays a list of all running processes, sorted uniquely by name and showing their process IDs.

Find Process Path (e.g., Firefox)
```powershell
Get-Process firefox | Sort-Object Unique | Format-List Path
```
Gets detailed information on the Firefox process, including its file path.

--- 

## System Information

#### Get Operating System Details

```powershell
Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property *
```

Retrieves detailed information about the current OS using WMI (Windows Management Instrumentation). Useful for enumeration and privilege escalation checks.

## TCP Port Scanner
```powershell
$target = "192.168.1.1"
$ports = 1..1024

foreach ($port in $ports) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.Connect($target, $port)
        if ($tcp.Connected) {
            Write-Host "Port $port is OPEN" -ForegroundColor Green
            $tcp.Close()
        }
    } catch {}
}
```