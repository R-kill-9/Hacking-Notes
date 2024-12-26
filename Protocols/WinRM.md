**WinRM** (WindowsRemote Management) is a Windows-native protocol that allows remote management of machines using SOAP-based communication. It enables administrators to execute commands and scripts, manage services, and collect data from remote Windows devices. It typically uses port **5985** and **5986**.

## Evil-WinRM
`Evil-WinRM` can be used to connect to a Windows machine.

```bash
evil-winrm -i <TARGET_IP> -u <USERNAME> -p <PASSWORD>
```

## Netexec

| **Option**  | **Description**                                  |
| ----------- | ------------------------------------------------ |
| `-u`        | Single username or file with a list of usernames |
| `-p`        | Single password or file with a list of passwords |
| `-t`        | Target IP or hostname                            |
| `--port`    | Specify custom WinRM port                        |
| `--timeout` | Set timeout for each connection attempt (s)      |
| `--verbose` | Enable detailed output during brute force        |

#### Validating Access 
To confirm valid credentials for WinRM, `netexec` can be used.

```bash
netexec winrm <target> -u <username> -p <password>
```

#### Brute Force Attack   
`netexec` can be used to perform brute force attacks on WinRM.

```bash
netexec winrm -u <username_wordlist> -p <password_wordlist> -t <target-ip>
```

