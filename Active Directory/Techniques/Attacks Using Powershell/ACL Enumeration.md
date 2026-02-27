Active Directory uses Access Control Lists (ACLs) to define which identities can interact with directory objects.

Each object (user, group, OU, domain, etc.) contains permissions composed of:

- **ACL (Access Control List)** → full permission set on an object
    
- **ACE (Access Control Entry)** → individual permission rule
    
- **Security Principal** → user, group, or computer account
    
- **SID (Security Identifier)** → internal identity reference
    
- **Rights** → actions allowed over the object
    

ACL enumeration is performed to discover:

- Privilege escalation paths
    
- Delegated administration abuse
    
- Hidden administrative control
    
- Domain takeover paths
    

---

## Tools Used

There are two main approaches:

|Method|Description|
|---|---|
|PowerView|Offensive AD enumeration framework (recommended)|
|Native PowerShell|Built-in cmdlets available on domain systems|

---

## Loading PowerView (Required First)

PowerView is not native to Windows and must be loaded into memory.

```powershell
Import-Module .\PowerView.ps1
```

After importing, PowerView cmdlets become available, such as:

- `Convert-NameToSid`
    
- `Get-DomainObjectACL`
    
- `Get-DomainGroup`
    

Always verify module loading:

```powershell
Get-Command *Domain*
```

---

## Enumeration Strategy

Avoid enumerating the entire domain immediately.

Recommended process:

1. Start from a controlled user
    
2. Identify its SID
    
3. Enumerate objects it controls
    
4. Identify exploitable rights
    
5. Pivot into newly controlled identities
    
6. Follow nested group relationships
    
7. Search for domain-level permissions
    

---

## Step 1 - Obtain the User SID

ACLs reference identities using SIDs, not usernames.

### Using PowerView

```powershell
$sid = Convert-NameToSid <controlled_user>
```

## Native PowerShell Alternative

```powershell
(Get-ADUser <username>).SID
```

Requires RSAT / ActiveDirectory module.

---

## Step 2 - Enumerate ACLs for That Identity

ACL permissions may not always appear when enumerating the entire domain.  
Some environments restrict visibility or the ACE exists only on specific objects.

For this reason, enumeration should combine **broad searches** and **targeted object queries**.

### Using PowerView (Primary Method)

```powershell
Get-DomainObjectACL -ResolveGUIDs -Identity * |
Where-Object {$_.SecurityIdentifier -eq $sid}
```

This searches all domain objects and returns permissions assigned to the user.

`-ResolveGUIDs` converts internal permission GUIDs into readable rights such as:

- GenericAll
    
- WriteDACL
    
- AddMember
    
- ForceChangePassword
    

Without this flag, permissions may appear only as raw GUID values, making analysis difficult.

### Targeted Enumeration (Important Technique)

If wildcard enumeration does not return results, query specific objects directly.

```powershell
Get-DomainObjectACL -ResolveGUIDs -Identity "<target object>" |
Where-Object {$_.SecurityIdentifier -eq $sid}
```

This approach is important because:

- ACLs are stored per object
    
- Some ACEs are only visible when querying the object itself
    
- Targeted searches reduce noise and improve accuracy
    
- This mirrors how BloodHound identifies relationships internally
    

#### Understanding the Output

Important fields:

- **ObjectDN** → target object
    
- **ActiveDirectoryRights** → permission category
    
- **ObjectAceType** → specific right
    
- **SecurityIdentifier** → identity holding the permission
    
- **AceQualifier** → Allow or Deny
    

### Manual GUID Resolution

If GUID resolution is unavailable or Powerview cannot be used:

#### Native PowerShell

```powershell
$guid = "<GUID_VALUE>"

Get-ADObject `
 -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" `
 -Filter {ObjectClass -like 'ControlAccessRight'} `
 -Properties rightsGuid |
 Where-Object {$_.rightsGuid -eq $guid}
```

---

## Step 3 - Enumeration Without PowerView (Restricted Environments)

Useful when external tools cannot be imported.

### Create List of Domain Users

```powershell
Get-ADUser -Filter * |
Select -ExpandProperty SamAccountName > users.txt
```

### Enumerate ACLs Manually

```powershell
foreach($user in Get-Content users.txt)
{
    Get-Acl "AD:\$(Get-ADUser $user)" |
    Select -ExpandProperty Access |
    Where-Object {
        $_.IdentityReference -match "<controlled_user>"
    }
}
```

Characteristics:

- Slow execution
    
- High noise
    
- Works using only native capabilities
    

---

## Step 4 - High-Value Rights to Identify

|Permission|Meaning|
|---|---|
|GenericAll|Full control over object|
|GenericWrite|Modify attributes or memberships|
|WriteDACL|Modify permissions|
|WriteOwner|Take ownership|
|ForceChangePassword|Reset password without current password|
|AddMember|Add users to groups|
|ExtendedRight|Special delegated privilege|

---

## Step 5 - Pivoting After Gaining Control

Once a new user or group becomes controllable, repeat enumeration.

### PowerView

```powershell
$sid2 = Convert-NameToSid <new_identity>

Get-DomainObjectACL -ResolveGUIDs -Identity * |
Where-Object {$_.SecurityIdentifier -eq $sid2}
```

ACL attacks are iterative.

---

## Step 6 - Enumerate Group Nesting

Group nesting often creates indirect privilege escalation.

### PowerView

```powershell
Get-DomainGroup -Identity "<group_name>" | Select memberof
```

### Native Alternative

```powershell
Get-ADGroup "<group_name>" -Properties MemberOf
```

Users inherit permissions from all parent groups.