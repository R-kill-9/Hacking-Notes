The **Remote Procedure Call (RPC)** protocol enables software to execute code on a remote system as if it were local. In a Windows environment, RPC is integral to communication between services and client machines, often used for managing resources, retrieving system information, and interacting with Active Directory.

## Rpcclient
`rpcclient` is a tool in the Samba suite used to interact with Windows machines and enumerate information about SMB shares, user accounts, groups, and other domain-related data. 

#### Connecting to a Target

| Option          | Description                                                                                             |
|-----------------|---------------------------------------------------------------------------------------------------------|
| `-U <username>` | Specifies the username to authenticate with.                                                            |
| `<target_ip>`   | The IP address of the target machine.                                                                   |
| `-N`            | Attempts an anonymous login to the target machine.                                                      |

```bash
rpcclient -U <username> <target_ip>
```

#### Basic Domain Enumeration

| Command              | Description                                                                    |
| -------------------- | ------------------------------------------------------------------------------ |
| `enumdomusers`       | List all domain users.                                                         |
| `queryuser <RID>`    | Show detailed info about a user (after obtaining the RID from `enumdomusers`). |
| `lookupnames <name>` | Get the RID of a specific user or group.                                       |
| `lookupids <RID>`    | Reverse lookup of a RID to a username/group.                                   |
| `enumdomgroups`      | List all domain groups.                                                        |
| `querygroup <RID>`   | Detailed info about a group.                                                   |
| `enumdomaliases`     | List local domain aliases.                                                     |
| `lsaquery`           | Get the domain name and its SID.                                               |
| `srvinfo`            | Get OS and server info (Windows version, build, etc.).                         |

#### User & Group Details

| Command                 | Description                                     |
| ----------------------- | ----------------------------------------------- |
| `getusername`           | Show the current logged-in username and domain. |
| `queryusergroups <RID>` | List all groups a user belongs to.              |
| `querygroupmem <RID>`   | List all members of a group.                    |
| `enumprivs`             | Enumerate domain privileges.                    |
#### System & Policy Info

|Command|Description|
|---|---|
|`getdompwinfo`|Retrieve password policy (min length, lockout, etc.).|
|`getdcname`|Get the primary domain controller name.|
|`netshareenum`|List all SMB shares (even hidden ones, if accessible).|
|`netsharegetinfo <sharename>`|Get details about a specific share.|
|`netfileenum`|Enumerate open files on the server.|
|`enumdrivers`|Enumerate printer drivers (may leak file paths).|
|`enumports`|Enumerate printer ports.|