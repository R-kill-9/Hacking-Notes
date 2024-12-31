In Linux, **capabilities** are a way to divide the traditional privileges of the **root** user into more specific and granular permissions. Typically, a process that needed to perform privileged tasks in Linux had to run with full **root** privileges. However, with **Linux Capabilities**, specific privileges can be granted to a process without giving it full access to all system resources, as would normally be the case with the root user.

## Common Capabilities

Here are a few examples of common **capabilities**:

- **`CAP_NET_BIND_SERVICE`**: Allows a program to bind to privileged ports (ports below 1024) without requiring root access.
- **`CAP_SYS_TIME`**: Allows a process to change the system's time.
- **`CAP_SETUID`**: Allows a process to change its **User ID** (UID), potentially to root, allowing it to act as a different user.
- **`CAP_SYS_ADMIN`**: A broad capability that gives access to various administrative system functions.

## How Are Capabilities Used in Linux

You can view and modify the capabilities of a file using commands like **`getcap`** and **`setcap`**.

- View the capabilities assigned to a file:
```bash
getcap /path/to/file
```
- Assign a capability to a file:
```bash
sudo setcap cap_net_bind_service+ep /path/to/file
```
In this command:

- **`cap_net_bind_service`** is the capability being granted.
- **`+ep`** means the capability is enabled (Effective) and permitted.

## Exploiting binaries with capabilities:

- **Example of `cap_setuid`**: If a binary has the **`cap_setuid`** capability, it can change its **User ID** (UID), potentially to root. An attacker could use this to execute commands as root. For instance, if the binary `python3.8` has the `cap_setuid` capability, the attacker could write a script to change the UID to `0` (root) and spawn a root shell:
```bash
import os
os.setuid(0)
os.system("/bin/bash")
```
- **Example of `cap_net_bind_service`**: While not as critical as `cap_setuid`, this capability allows an attacker to bind a service to a privileged port. This could be used to run a rogue service on important ports like **80** (HTTP) or **443** (HTTPS), potentially aiding in further attacks or data exfiltration.