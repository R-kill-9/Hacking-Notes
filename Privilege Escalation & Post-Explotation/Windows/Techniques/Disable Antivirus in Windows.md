In penetration testing and post‑exploitation scenarios, **Windows Defender (Microsoft Defender Antivirus)** may block payloads such as reverse shells, scripts, or binaries.  
Disabling or bypassing antivirus protection is sometimes required **after gaining sufficient privileges**.

> **Important:** These techniques apply to **authorized environments only** (labs, CTFs, red team with permission).


---

## Disable Real‑Time Protection (PowerShell)

### Disable Real‑Time Monitoring

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

- Disables Defender’s real‑time scanning
    
- Commonly used during post‑exploitation
    
- Often temporary (may re‑enable automatically)
    

### Check Defender Status

```powershell
Get-MpComputerStatus
```

Useful fields:

- `RealTimeProtectionEnabled`
    
- `AntivirusEnabled`
    
- `AMServiceEnabled`
    

---

## Disable via Windows Security (GUI)

If GUI access is available:

1. Open **Windows Security**
    
2. Go to **Virus & threat protection**
    
3. Click **Manage settings**
    
4. Disable **Real‑time protection**
    

> This method is usually blocked without admin rights.

---

## Tamper Protection

Modern Windows versions include **Tamper Protection**, which prevents Defender settings from being changed.

- Enabled by default on Windows 10/11
    
- Must be disabled manually from GUI:
    
    - Windows Security → Virus & threat protection → Manage settings → Tamper Protection
        

If Tamper Protection is enabled:

- `Set-MpPreference` may fail
    
- Registry changes are ignored
    

---

## Exclusions (Stealthier Option)

Instead of disabling AV completely, adding **exclusions** is often quieter.

### Add Path Exclusion

```powershell
Add-MpPreference -ExclusionPath "C:\Temp"
```

### Add Process Exclusion

```powershell
Add-MpPreference -ExclusionProcess "powershell.exe"
```

Exclusions:

- Reduce detection
    
- Less suspicious than fully disabling Defender
    
- Still require admin privileges
    


---

## Re‑Enable Windows Defender
After post‑exploitation tasks are completed, **Windows Defender should be re‑enabled** to restore the system to its original security state (especially in labs, exams, or professional engagements).

### Re‑Enable Real‑Time Protection (PowerShell)

#### Enable Real‑Time Monitoring

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
```

This:

- Re‑enables Defender’s real‑time scanning
    
- Restores normal antivirus behavior
    



### Verify Defender Status

```powershell
Get-MpComputerStatus
```

Check the following fields:

- `RealTimeProtectionEnabled` → should be `True`
    
- `AntivirusEnabled` → should be `True`
    
- `AMServiceEnabled` → should be `True`
    


