Meterpreter is an advanced and flexible payload used in **Metasploit Framework**, designed for post-exploitation tasks after successfully exploiting a target system. It allows attackers (or ethical hackers) to interact with and control the compromised system remotely, offering numerous features for pivoting, escalation, and lateral movement.

## Common Meterpreter Commands

1. **Basic Commands**:
- `sysinfo`: Displays system information (OS, architecture, logged-in users).
- `getuid`: Displays the current user ID.
- `shell`: Opens a system shell for further command execution.
2. **File Management**:
- `upload <local_path> <remote_path>`: Uploads files to the target system.
- `download <remote_path> <local_path>`: Downloads files from the target system.
3. **Network & Post-Exploitation**:
- `portfwd`: Forwards ports between the target machine and the attacker's machine.
- `route`: Manages routes for pivoting through compromised systems to reach other targets on the same network.
4. **Privilege Escalation**:      
- `getsystem`: Attempts to escalate privileges to SYSTEM.
- `migrate`: Migrates the Meterpreter session to another process (often a more stable one).
6. **Keylogging**:    
- `keyscan_start`: Starts logging keystrokes on the victim's system.
- `keyscan_dump`: Displays the captured keystrokes.

## Ensuring the escalation
When you gain access to a Windows machine through Meterpreter, one of the first things you should do is ensure persistence and escalate your privileges. Here's why and how you can use pgrep explorer and migrate commands.

- **Identify a Suitable Process (pgrep explorer)**:  
    After gaining access to the machine, it's essential to search for processes that run with higher privileges or are more stable, such as **Explorer.exe**. Using **`pgrep explorer`**, you can find the **PID (Process ID)** of **Explorer.exe**. This process is typically running with user-level privileges, but it's often more stable and trusted by the system compared to other processes.
    
- **Migrate to a Trusted Process (migrate)**:  
    Once you have the **PID** of **Explorer.exe**, use the **`migrate <PID>`** command to move your Meterpreter session to that process.

## Ensuring correct payload
Verify that you are using the correct payload that matches the architecture of the target system (32-bit vs. 64-bit). For instance:
- For 32-bit systems, use `windows/meterpreter/reverse_tcp`.
- For 64-bit systems, use `windows/x64/meterpreter/reverse_tcp`.

If the wrong payload is used, you may establish a connection but fail to create the Meterpreter session, as the payload will not be compatible with the target architecture.

