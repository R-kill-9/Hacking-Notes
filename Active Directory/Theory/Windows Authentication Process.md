![](../../Images/Windows_authentication_process.png)

This diagram represents the **Windows authentication flow from credential input to session creation**.  
It shows how Windows processes credentials using **WinLogon**, **LSASS**, **authentication packages**, and **NTLM/Kerberos**, depending on whether the system is **local** or **domain-joined**.

---

## 1️. Credential Collection (WinLogon → LogonUI → Credential Provider)

### WinLogon.exe

- Main controller of the logon process.
    
- Uses **Secur32.dll** to interact with Windows security APIs.
    
- Handles the Secure Attention Sequence (Ctrl+Alt+Del).
    

### LogonUI

- Displays the Windows logon interface.
    
- Does **not** authenticate users.
    
- Requests credentials through Credential Providers.
    

### Credential Provider

- Collects authentication material:
    
    - Username
        
    - Password / PIN / Smart Card
        
- Sends credentials back to **WinLogon**.
    

At this stage, credentials are **collected but not validated**.

---

## 2️. Credential Validation (WinLogon → LSASS → Authentication Packages)

### LSASS.exe (Local Security Authority Subsystem Service)

- Core Windows authentication service.
    
- Loads **lsasrv.dll**.
    
- Enforces security policies.
    
- Chooses the appropriate authentication mechanism.
    

### Authentication Packages

- Plug-in modules used by LSASS.
    
- Determine whether authentication is:
    
    - **Local / Non-domain joined**
        
    - **Remote / Domain joined**
        


### Local / Non-Domain Joined Authentication Path

```
Authentication Packages
   ↓
Local / Non-Domain joined
   ↓
NTLM
   ↓
SAM
   ↓
Registry
```

#### NTLM

- Implemented via **msv1_0.dll**.
    
- Validates local credentials using password hashes.
    

#### SAM (Security Account Manager)

- Implemented by **samsrv.dll**.
    
- Stores local users and password hashes.
    

#### Registry

- SAM database is backed by the Windows Registry.

> This method is used for: Standalone machines or Local user accounts


### Remote / Domain Joined Authentication Path

```
Authentication Packages
   ↓
Remote / Domain joined
   ↓
Kerberos (preferred)
   ↓
Netlogon
   ↓
Active Directory Services
```

#### Kerberos

- Implemented by **kerberos.dll**.
    
- Default authentication protocol in Active Directory environments.
    
- Uses ticket-based authentication (TGT / TGS).
    

#### NTLM (Fallback)

- Used if Kerberos authentication is not possible.
    

#### Netlogon

- Implemented via **netlogon.dll**.
    
- Establishes a secure channel with the Domain Controller.
    

#### Active Directory Services

- Uses **ntds.dit** (via **ntdsa.dll**).
    
- Stores and validates domain credentials.
    

> This method is used for: Domain-joined systems or Enterprise networks

---

## 3️. Session Creation (Post-Authentication)

Once authentication succeeds, **WinLogon continues the process**:

```
WinLogon
 └─ CreateDesktop()
     ├─ Load Profile
     │    └─ Load Registry (NTUSER.DAT)
     └─ userinit.exe
          └─ explorer.exe
```

### CreateDesktop()

- Creates the interactive desktop session.
    

### Load Profile / Load Registry

- Loads the user profile.
    
- Mounts **NTUSER.DAT** into the registry.
    

### userinit.exe → explorer.exe

- userinit.exe initializes the session.
    
- explorer.exe launches the Windows shell.
    
