Once administrative access is obtained in an Active Directory (AD) domain, identifying systems related to virtualization and backup is essential for privilege escalation, lateral movement, and data exfiltration. These systems often hold elevated privileges, sensitive data, or control over critical infrastructure.


---

## Host Enumeration via PowerShell

### Script: Keyword-Based Host Discovery

```powershell
$keywords = @("vm", "vmware", "citrix", "bck", "backup", "copia")
$computers = Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name
$result = $computers | Where-Object {
    $name = $_.ToLower()
    $keywords | ForEach-Object { if ($name -match $_) { return $true } }
}
if ($result) {
    Write-Host "Equipos encontrados con palabras clave:" -ForegroundColor Cyan
    $result | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
} else {
    Write-Host "No se encontraron equipos con las palabras clave especificadas." -ForegroundColor Red
}
```

**Purpose:** Identify domain-joined machines likely associated with virtualization platforms (e.g., VMware, Citrix) or backup systems (e.g., Veeam, Commvault).


---


## Deep Enumeration Targets

### Virtualization Infrastructure

- **Service Discovery:**
```powershell
Get-Service -ComputerName <target> | Where-Object { $_.DisplayName -match "VMware|Citrix|Hyper-V" }
```

- **Installed Software:**
```powershell
Get-WmiObject -Class Win32_Product -ComputerName <target> | Where-Object { $_.Name -match "VMware|Citrix|Veeam" }
```

- **Group Memberships:**
```powershell
Get-ADGroupMember -Identity "VMware Admins"
```

- **GPO Enumeration:**
```powershell
Get-GPOReport -All -ReportType XML | Select-String "VMware|Citrix|Backup"
```



### Backup Infrastructure

- **Backup Agent Detection:**
```powershell
Get-WmiObject -Class Win32_Service -ComputerName <target> | Where-Object { $_.Name -match "Veeam|Commvault|BackupExec" }
```

- **Group Memberships:**
```powershell
Get-SmbShare -CimSession <target> | Where-Object { $_.Name -match "backup|bck|copia" }
```

- **GPO Enumeration:**
```powershell
Get-ScheduledTask -ComputerName <target> | Where-Object { $_.TaskName -match "backup|snapshot" }
```



---

## Credential Harvesting

- **Service Account Identification:**
    
    - Look for accounts with naming conventions like `svc_vmware`, `svc_veeam`, `backup_admin`.
        
- **Credential Dumping:**
    
    - Use Mimikatz or LSASS memory extraction on backup and virtualization servers.
        
- **Token Impersonation:**
    
    - Leverage `Invoke-TokenManipulation` to impersonate privileged service accounts.

