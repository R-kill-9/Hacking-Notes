#### Common Log Locations in Windows

Windows stores logs in the **Event Viewer**. The main categories include:

- **Application Logs**: Logs related to application events.
- **Security Logs**: Logs for auditing and login events.
- **System Logs**: Logs for Windows system components and events.

Log files are stored in the directory `C:\Windows\System32\winevt\Logs\`

## Using Command Prompt (Wevtutil

The `wevtutil` command-line tool allows managing event logs.

**Clear a specific log:**
```bash
wevtutil cl <log_name>
```

Example:

```bash
wevtutil cl Security
```

**List all log names:**

```bash
wevtutil el
```

## Using Metasploit

Metasploit offers a module to clear logs on a target system.

1. Gain a Meterpreter session on the target.
2. Use the following command:
```bash
clearev
```