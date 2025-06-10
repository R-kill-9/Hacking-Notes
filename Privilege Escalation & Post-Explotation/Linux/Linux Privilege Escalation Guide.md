> For a deeper understanding and detailed techniques on each topic, review the expanded content available in the **Techniques** directory.
## Reconnaissance
Gather basic system and user information to understand the environment.

```bash
whoami                 # Current user
id                     # User and group details
hostname               # Hostname
uname -a               # Kernel and system architecture info
cat /etc/os-release    # OS version and details
```

## Environment Variables and PATH Hijacking
Review environment variables, especially PATH, for opportunities to inject malicious binaries.

```bash
env                                 # List all environment variables
echo $PATH                          # Check PATH variable
```

## User and Group Enumeration
Check user privileges and group memberships.
```bash
groups                 # Groups current user belongs to
getent group sudo      # Users in sudo group
cat /etc/passwd        # List of system users
```

## Sudo Permissions
Identify commands you can run with sudo and if a password is required.
```bash
sudo -l                # List allowed sudo commands for the current user
```

## File Permissions and SUID Binaries
Look for files and binaries with special permissions that could be exploited.

```bash
find / -perm -4000 -type f 2>/dev/null   # Find all SUID binaries
find / -writable -type d 2>/dev/null     # Writable directories for current user
```

## Scheduled Tasks (Cron Jobs)
Check for cron jobs running as root or other privileged users.

```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l                             # Current user's cron jobs
```

## Network Information
Identify active network connections and services.

```bash
netstat -tuln                         # Open ports and listening services
ss -tuln                             # Alternative to netstat
ps aux                              # Running processes
```

## Linux Capabilities
Look for binaries with special Linux capabilities set.

```bash
getcap -r / 2>/dev/null           # Find files with capabilities
```

## Log Files
Review system logs for sensitive information or clues.

```bash
cat /var/log/auth.log             # Authentication logs (Debian-based)
cat /var/log/secure               # Authentication logs (RedHat-based)
cat /var/log/syslog              # System logs
```


## Docker and Containers
If Docker is installed, sometimes users in docker group can escalate privileges.

```bash
groups | grep docker
docker ps
docker run -v /:/host -it alpine chroot /host sh  # Example of Docker escape (if permitted)
```

## Virtual Hosts Enumeration

Check for additional virtual hosts configured in web servers like nginx or Apache. This can reveal hidden websites or admin panels.

```bash
ls /etc/nginx/sites-enabled/
cat /etc/nginx/sites-enabled/*       

ls /etc/apache2/sites-enabled/
cat /etc/apache2/sites-enabled/*     
```

## Automated Enumeration Tools

**linpeas:** A comprehensive script that automates the enumeration process to identify potential privilege escalation vectors.

**pspy:** Tool to monitor processes and cron jobs without needing root privileges, useful to detect privilege escalation opportunities in real time.

```bash
./linpeas.sh
./pspy64
```

