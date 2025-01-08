## Gathering Basic System Information

- **`uname -a`**   
Displays detailed system information, including the kernel version and architecture.

```bash
uname -a
```

- **`cat /etc/os-release`**  
Shows the Linux distribution details.

```bash
cat /etc/os-release
```

- **`hostname`**  
Displays the system's hostname.
```bash
hostname
```

- **`whoami`**  
Shows the current logged-in user.
```bash
whoami
```

- **`dpkg -l`** 
Lists installed packages.

```bash
dpkg -l
```

- **`df -h`**  
Displays disk usage in a human-readable format.
```bash
df -h
```

- **`lsblk`**  
Lists out all block devices in a tree-like format.
```bash
lsblk
```

## User and Group Enumeration

- **`id`**  
Displays the current user ID (UID), group ID (GID), and groups the user belongs to.

```bash
id
```

- **`who`**  
Lists all logged-in users.

```bash
who
```

- **`last`**  
Displays login history.

```bash
last
```

- **`cat /etc/passwd`**  
Shows all system users.
```bash
cat /etc/passwd
```

- **`cat /etc/group`**  
Lists all groups and their members.

```bash
cat /etc/group
```


## Network Configuration


- **`ip a`** _(or `ifconfig`)_  
Displays network interfaces and their configurations.

```bash
ip a
ifconfig
```

- **`route -n`** _(or `ip route`)_  
Displays the system's routing table.

```bash
route -n
ip route
```

- **`netstat -tuln`** _(or `ss -tuln`)_  
Lists active network connections, including listening services.

```bash
netstat -tuln
ss -tuln
```

- **`arp -a`**  
Shows the ARP table.

```bash
arp -a
```

- **`cat /etc/hosts`** 
It is used to map domain names and IP addresses within a target system.

```bash
cat /etc/hosts
```


## Processes and Cron Jobs

- **`ps aux`**  
Lists all running processes.

```bash
ps aux
```

- **`top`** or **`htop`**  
Displays an interactive view of system resource usage.

```bash
top
htop
```

- **`service --status-all`**  
Lists the status of all services.

```bash
service --status-all
```

- **`cat /etc/crontab`**  
Lists the existent cron jobs.

```bash
cat /etc/crontab
```
