**Domain trusts** are mechanisms in Active Directory that allow authentication between separate domains or forests without requiring identity migration. They are widely used in enterprise environments where companies merge, acquire subsidiaries, or maintain separated infrastructures that still need shared access to resources.

From a technical and security standpoint, a trust extends the authentication boundary beyond a single domain. This means that a compromise in one trusted environment can potentially affect another. During security assessments, trusted domains frequently provide alternative attack paths when the primary domain is hardened.

---

## Purpose of Domain Trusts

A trust allows a domain controller to accept authentication decisions made by another domain. Users authenticate in their own domain but can request access to resources located elsewhere.

Trust configuration defines:

- authentication direction (who trusts whom)
    
- scope of trust propagation
    
- filtering and validation of identities
    

These parameters directly influence lateral movement possibilities across environments.

---

## Trust Types

Active Directory implements several trust models depending on organizational structure:

- **Parent–Child Trust**  
    Automatically created inside a forest when a new domain is added. Bidirectional and transitive by default.
    
- **Cross-Link Trust**  
    Direct trust between child domains to speed authentication and avoid hierarchy traversal.
    
- **External Trust**  
    Connects domains from different forests without full forest integration. Usually non-transitive and more restrictive.
    
- **Tree-Root Trust**  
    Created when introducing a new tree root domain within a forest. Transitive and bidirectional.
    
- **Forest Trust**  
    Connects two forest root domains, allowing authentication across entire forests.
    
- **ESAE (Bastion Forest)**  
    A hardened administrative forest used to manage privileged accounts securely.
    

---

## Transitivity

Trusts define whether authentication extends beyond directly connected domains.

- **Transitive trust:**  
    Trust relationships propagate automatically. If A trusts B and B trusts C, then A implicitly trusts C.
    
- **Non-transitive trust:**  
    Authentication applies only between the two configured domains.
    

Transitive trusts simplify enterprise authentication but increase potential attack surface.

---

## Trust Direction

Trust direction controls authentication flow:

- **One-way trust:** users from one domain access another, but not the opposite.
    
- **Bidirectional trust:** both domains authenticate each other’s users.
    

Bidirectional trusts are operationally convenient but increase risk because compromise in either domain may enable cross-domain movement.

---

## Security Considerations

Trusts are often introduced for operational convenience and later forgotten. Common real-world risks include:

- insecure acquired environments
    
- outdated partner relationships
    
- excessive bidirectional trusts
    
- privilege relationships spanning domains
    

Attackers frequently exploit weaker trusted domains to indirectly access a stronger primary domain. Techniques like Kerberoasting or credential abuse may work across trusts if authentication is allowed.

---

## Enumerating Domain Trusts

Once access to a system is obtained, identifying trust relationships is critical to understand expansion paths.

#### Built-in Active Directory PowerShell

Import the AD module and enumerate trusts:

```powershell
Import-Module ActiveDirectory
Get-ADTrust -Filter *
```

Important properties to analyze:

- `Direction` → one-way or bidirectional
    
- `IntraForest` → indicates same-forest (parent/child)
    
- `ForestTransitive` → forest-level trust
    
- `SelectiveAuthentication` → authentication restrictions

#### PowerView Enumeration

PowerView provides clearer mapping of trust relationships:

```powershell
Get-DomainTrust
```

Mapping authentication paths:

```powershell
Get-DomainTrustMapping
```

After confirming authentication is allowed, enumeration can continue into trusted domains:

```powershell
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL
```


#### Native Windows Tool — netdom

Useful when only built-in binaries are allowed:

```bash
netdom query /domain:inlanefreight.local trust
```

Additional enumeration:

```bash
netdom query /domain:inlanefreight.local dc
netdom query /domain:inlanefreight.local workstation
```

These commands reveal trusts, domain controllers, and domain-joined systems.


#### LDAP Enumeration with NetExec 

Trust relationships can also be enumerated via LDAP using NetExec:

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M enum_trusts
```
