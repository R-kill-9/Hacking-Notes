It is a network protocol tool that allows users to communicate with remote computers and servers to use their resources or share, open, and edit files.

- `-U` access as user.
- `-N` No password.
- `-L` This option allows you to look at what services are available on a server.

```bash
smbclient -U bob //10.129.42.253/users
# You can list resources without user with this command:
smbclient -N -L //10.129.117.14/
```

To **list the contents of a specific directory** inside a shared resource on the server:

1. Connect to the shared resource using `smbclient`.
2. Once inside, use the `ls` command to view the contents of the current directory.

```bash
smbclient //10.129.42.253/users -U bob
smb: \> ls
```

To download all content from a shared resource using `smbclient`, you can use the `mget *` command, which downloads all files in the current directory.

```bash
smb: \> mget *
```

To download all files and directories you need to execute these commands:

```bash
# Enable recursive download
smb: \> recurse ON
# Turn off interactive prompts for each file
smb: \> prompt OFF
# Download all files and folders
smb: \> mget *
```

