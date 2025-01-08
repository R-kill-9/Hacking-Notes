When working in a restricted or limited shell session, upgrading to a fully interactive shell can provide advanced features like:

- Full control of function keys (e.g., arrow keys).
- Command history and editing.
- Ability to use interrupts like `Ctrl+C` and `Ctrl+Z`.

This is particularly useful for environments where interactivity is limited, such as reverse shells or when working within restricted environments.


---
## Verify Available Shells

Before attempting to spawn an interactive shell, check which shells are available on the system. 

```bash
cat /etc/shells
```
From this list, choose a suitable shell (commonly `/bin/bash`).

## Using Python to Spawn an Interactive Shell

1. **Python Command**:  
The following Python one-liner spawns a new instance of a fully interactive `/bin/bash` shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

2. **Restarting to Apply Changes**:  
After spawning the shell, we need to restart and configure the terminal properly. 

- Suspend the shell with `Ctrl+Z`.
- Run the following commands in the limited shell:

```bash
stty raw -echo; fg  
reset xterm
export TERM=xterm
export SHELL=bash
```