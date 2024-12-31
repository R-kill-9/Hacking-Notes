## Escalation ideas 
https://github.com/RoqueNight/Linux-Privilege-Escalation-Basics

## gtfobins
GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
link -> https://gtfobins.github.io

## sudo -l
Command used to know what commands can be executed as root by the actual user.

## linpeas.sh
It is a script designed to assist in privilege escalation enumeration on Linux systems.
Linpeas is written in Bash scripting language and is designed to be executed directly on the target Linux system. It automates the process of gathering information and performing various checks to identify potential privilege escalation vectors.
**It's important paying attention to all the fields, specially the capabilities**
```bash
./linpeas.sh
```

## pspy
**pspy** is based on the analysis of the `/proc` directory, which contains information about the running processes in the Linux operating system. It utilizes the virtual file system `/proc` to obtain real-time information about processes, such as the process ID, process name, user executing the process, files opened by the process, and other relevant details.
```bash
./pspy
```


## /etc/hosts
This file can be a valuable resource for mapping domain names to IP addresses within a target system.
For example, we could find a new subdomain.
```bash
ls /etc/hosts
```

## /proc/version
The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.

Looking at `/proc/version` may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.
This can be useful if you want to find a possible CVE.

## id
Something we can do to gain privileges is to observe the groups our current user belongs to, to see if there's any uncommon one and take advantage of it to exploit a vulnerability.
```bash
#command:
id                                     
#possible output:
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```
If we observe the output, we can see that Robert is in the bugtracker group, what it's not common.

## locate
It is a command that locates if there is any file with this name. This can be useful, for example, if we want to locate a user or a group.
```bash
#command:
locate bugtracker
#possible output:
/usr/bin/bugtracker
```


