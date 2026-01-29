**LDAP** (Lightweight Directory Access Protocol) is a protocol used for accessing and managing directory information. It allows searching, retrieving, and modifying information in a directory, such as user accounts, groups, permissions, and other objects within a network. LDAP is commonly used in enterprise environments, particularly with Microsoft Active Directory, to centralize identity and access management.

## ldapsearch
- **Anonymous Search**: Attempt to retrieve information without credentials:
```bash
ldapsearch -x -H ldap://<server_ip> -b "dc=example,dc=com"
```

- Find users with specific attributes (like emails):
```bash
ldapsearch -x -H ldap://<server_ip> -b "dc=example,dc=com" "(objectClass=person)" mail
```
## ldapenum
To enumerate all users in an LDAP directory:

```bash
ldapenum -u <username> -p <password> -H ldap://<server_ip>
```

## ldapdomaindump
This tool connects to an LDAP server and retrieves information related to users, groups, computers, policies, and other objects within **Active Directory**. It generates detailed reports, typically in **HTML** or **JSON** format, to facilitate the analysis of the extracted data. This tool is highly useful for enumerating domain data without requiring a privileged account, as it can work with a basic account that has read permissions (in many AD configurations, read access is available to low-level accounts).

### Installation

You can install `ldapdomaindump` using **pip**:
```bash
pip install ldapdomaindump
```

### Basic Usage
| Option                      | Description                                                                                               |
|-----------------------------|-----------------------------------------------------------------------------------------------------------|
| `-u "<DOMAIN>\<USERNAME>"`   | The user used for authentication. Be sure to include the domain, e.g., `cicada\john.doe`.                |
| `-p "<PASSWORD>"`            | The user's password for authentication.                                                                  |
| `<SERVER_IP>`                | The IP address of the LDAP server or domain controller.                                                  |

```bash
ldapdomaindump -u "<DOMAIN>\<USERNAME>" -p "<PASSWORD>" <SERVER_IP>
```

## Nmap
- Discover open LDAP ports and services:
```bash
nmap -p 389,636 <target_ip>
```

- Script scanning for LDAP:
```bash
nmap -p 389 --script ldap* <target_ip>
```


## Hydra
Perform brute-force attacks on LDAP authentication:
```bash
hydra -L <username_list> -P <password_list> ldap://<target_ip>
```