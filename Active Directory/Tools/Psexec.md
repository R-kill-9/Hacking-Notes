**PsExec** is a tool from the **Sysinternals Suite** developed by Microsoft. It is used to execute processes or commands on remote systems without requiring manual installation of client software.

#### Key Features

- Execute commands remotely on Windows systems.
- Copy and execute binaries to remote machines.
- Open interactive remote command prompts.
- Run processes as SYSTEM or other users.
- Work over SMB protocol for communication.

#### Usage

|Option|Description|
|---|---|
|`<target>`|Specifies the target machine. Use `\\*` for all machines in a domain.|
|`-u <user>`|Specifies the username for authentication (e.g., `-u Administrator`).|
|`-p`|Specifies the password for the given username.|
|`-s`|Runs the command as the SYSTEM account.|
|`-i`|Starts an interactive session on the target.|
|`-d`|Does not wait for the process to terminate. Useful for long-running tasks.|
|`-c`|Copies the executable file to the target system before running it.|
|`-h`|Runs the command with elevated privileges on the target.|
|`-v`|Verifies that the target binary is a valid image.|

```bash
impacket-psexec <user>@<target_ip> 
```

## Pass-the-Hash with PsExec
Pass-the-Hash (PtH) is an attack technique that leverages NTLM hashes to authenticate against remote systems without requiring plaintext passwords. PsExec, particularly in implementations like Impacket’s `psexec.py`, allows executing commands remotely using this method, making it a powerful tool for penetration testing and post-exploitation.

#### Steps for Pass-the-Hash with PsExec:

1. Obtain NTLM hashes of user credentials using tools like `mimikatz`, `hashdump`, or similar.
2. Use the NTLM hash in place of the password with tools like Impacket’s `psexec.py`.
3. Ensure the user account has administrative privileges on the target machine.
#### Execution
- Replace `<target-ip>` with the IP address of the target system.
- Replace `<NTLM_hash>` with the actual hash of the user's password.

```bash
python3 psexec.py Administrator@<target-ip> -hashes <NTLM_hash>
```