In Active Directory environments, access to objects is strictly controlled to prevent unauthorized interaction between users, computers, and resources. This control is implemented through **Access Control Lists (ACLs)**. Every AD object, including users, groups, computers, Organizational Units (OUs), and Group Policy Objects (GPOs), contains an ACL that defines authorization boundaries.

An ACL answers two fundamental questions:

- Who can access an object.
    
- What operations they are allowed to perform.


Permissions inside ACLs are implemented through **Access Control Entries (ACEs)**, where each ACE links a security principal (identified by SID) to a specific set of rights.

---

### ACL Structure and Types

Active Directory implements two main ACL categories, each serving a different security purpose.

**Discretionary Access Control List (DACL)**  
The DACL controls authorization. It contains ACEs that explicitly allow or deny access to an object. Whenever a user or process attempts access, Windows evaluates the DACL to determine effective permissions.

Important behavior rules:

- If no DACL exists → full access is granted.
    
- If a DACL exists but contains no ACEs → access is denied to everyone.
    
- Permissions are processed sequentially, and explicit deny entries override allows.

![](../../Images/DACL_theory.png)

**System Access Control List (SACL)**  
The SACL is used for auditing rather than authorization. It records access attempts and logs whether operations succeeded or failed. Administrators configure SACL auditing through the object’s Auditing tab.

---

## Access Control Entries (ACE)

An ACE is the fundamental permission unit inside an ACL. Each ACE specifies how a single principal interacts with a securable object.

Main ACE types:

- Access Allowed ACE — grants permissions.
    
- Access Denied ACE — explicitly blocks permissions.
    
- System Audit ACE — generates audit events.

Each ACE contains four technical components:

1. Security Identifier (SID) of the user or group.
    
2. ACE type flag (Allow, Deny, Audit).
    
3. Inheritance flags controlling propagation to child objects.
    
4. Access Mask, a 32-bit value defining granted rights.


Inheritance is especially important in AD because permissions applied at higher containers may automatically propagate to many descendant objects, sometimes creating unintended privilege exposure.

---

## Permission Evaluation Logic

When access is requested, Active Directory evaluates permissions using a deterministic order:

- ACL entries are processed from top to bottom.
    
- Explicit deny entries take precedence.
    
- Inherited permissions apply unless inheritance is blocked.
    
- Effective access results from combined permissions minus explicit denies.
    

Understanding this evaluation order is essential during privilege escalation analysis because attackers often rely on inherited or overlooked ACEs.

---

## Why ACLs Matter in Offensive Security

ACL abuse is a powerful attack vector because organizations rarely audit object permissions comprehensively. Traditional vulnerability scanners do not analyze AD authorization relationships, making ACL weaknesses highly persistent.

Attackers and penetration testers use ACE abuse to:

- Escalate privileges vertically.
    
- Move laterally between systems.
    
- Establish stealth persistence.
    
- Achieve domain compromise even in hardened environments.
    

Enumeration is typically performed using tools such as:

- BloodHound (graph-based privilege analysis)
    
- PowerView (PowerShell AD enumeration)
    
- Native AD management utilities
    

Example exploitable permissions include:

- `ForceChangePassword`
    
- `GenericAll`
    
- `GenericWrite`
    
- `WriteDACL`
    
- `WriteOwner`
    
- `AddSelf`
    
- `AllExtendedRights`
    

---

## High-Value ACE Permissions and Abuse Techniques

**ForceChangePassword**  
Allows resetting a user’s password without knowing the current one.

```
Set-DomainUserPassword -Identity targetUser -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
```

This provides immediate account takeover but should be used carefully during assessments.

**GenericWrite**  
Allows modification of writable attributes on an object. Common abuses include assigning an SPN to perform Kerberoasting or modifying group membership.

```
Set-DomainObject -Identity targetUser -SET @{servicePrincipalName='fake/spn'}
```

**AddSelf**  
Permits a user to add themselves to a group, often leading to privilege escalation if the group is privileged.

```
Add-DomainGroupMember -Identity "IT Admins" -Members attackerUser
```

**GenericAll**  
Provides full control over an object. Depending on the target type, an attacker can reset passwords, modify memberships, or manipulate delegation settings.

If applied to computer objects and LAPS is deployed, attackers may read local administrator passwords and pivot further inside the network.
