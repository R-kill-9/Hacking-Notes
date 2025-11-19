**AllowedToAct** refers to the Active Directory attribute **`msDS-AllowedToActOnBehalfOfOtherIdentity`** found on computer objects. It defines which accounts (users, groups, or service accounts) are authorized to **act on behalf of other identities** when accessing that resource. This mechanism is part of **Resource-Based Constrained Delegation (RBCD)**, introduced in Windows Server 2012.


---

## How It Works

1. The attribute is configured on the **resource object** (for example, a server or domain controller).
2. It contains a security descriptor listing principals allowed to impersonate other users.
3. When one of these principals requests a Kerberos ticket to the resource, the KDC checks the `AllowedToAct` attribute.
4. If permitted, the principal can impersonate another identity (such as `Administrator`) when connecting to the resource.

---

## Attack Scenario

- If an attacker compromises an account listed in `AllowedToAct`, they can:
    - Request Kerberos tickets for the target resource.
    - Impersonate privileged users (e.g., `Administrator`).
    - Use tools like **Rubeus** or **Impacket (getST.py)** to perform S4U2Self and S4U2Proxy operations.
    - Gain remote access with elevated rights using tools such as `psexec.py -k -no-pass`.

Example:

```bash
impacket-getST 'domain.local/attacker_account' -spn cifs/target.domain.local -impersonate Administrator -dc-ip <dc-ip>
```
