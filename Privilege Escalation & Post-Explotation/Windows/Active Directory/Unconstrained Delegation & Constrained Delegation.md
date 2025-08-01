## Unconstrained Delegation

Unconstrained Delegation allows a computer or service to impersonate any user who authenticates to it, **without restrictions**. It’s set via the `TRUSTED_FOR_DELEGATION` flag on a computer account.

#### Technical Behavior:

When a user authenticates to a service with unconstrained delegation, their **TGT (Ticket Granting Ticket)** is stored in memory. The service can then use that TGT to impersonate the user to any other service in the domain.

#### Typical Attack Flow (Unconstrained Delegation Abuse):

```bash
1. Attacker gains control over a computer with unconstrained delegation (CompA).
2. Wait for a high-privileged user (e.g., Domain Admin) to authenticate to CompA.
3. Extract the TGT from memory (e.g., with Rubeus).
4. Use the TGT to request service tickets (TGS) or impersonate the user across the domain.
```


---

## Constrained Delegation (S4U2Proxy / S4U2Self)

**Definition:**  
Constrained Delegation allows a service to impersonate users **only to specific services**, defined by `msDS-AllowedToDelegateTo`.

#### Two key Kerberos extensions involved:

- **S4U2Self**: Allows a service to request a service ticket on behalf of a user (without the user providing a TGT).
- **S4U2Proxy**: Allows the service to **use** that ticket to access another service **if it’s listed** in the delegation list.

#### Typical Attack Flow (Constrained Delegation Abuse with S4U):

```bash
1. Attacker controls a service account (e.g., svcApp) configured with Constrained Delegation.
2. Use S4U2Self to request a ticket for any user (e.g., Domain Admin).
3. Use S4U2Proxy to impersonate that user to another service listed in msDS-AllowedToDelegateTo (e.g., CIFS/DC).
```