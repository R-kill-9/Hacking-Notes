When we do a reverse shell, sometimes, we will need to upgrade our shell.

Specifically, what  is achieved with these commands is establishing a new interactive terminal with advanced features, such as full control of function keys, command history, and the ability to use commands like Ctrl+C and Ctrl+Z. This can be useful in situations where greater interactivity is needed in a limited shell session.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# we need to *restart* to apply the changes, so we do:  
CTRL+Z  
stty raw -echo; fg  
reset xterm
export TERM=xterm
export SHELL=bash
```
