## Rsync (Remote File Sync)
Rsync efficiently copies files between hosts using a delta-transfer algorithm. Default port: TCP 873. Often used with SSH for secure transfer.

**Footprinting – Detect Rsync service:**

```bash
sudo nmap -sV -p 873 <IP>
```

**Testing open shares:**

```bash
nc -nv <IP> 873
@RSYNCD: 31.0
#list
```

**List contents of a share:**

```bash
rsync -av --list-only rsync://<IP>/<share>
```

**Download files from a share:**

```bash
rsync -av rsync://<IP>/<share> ./local_directory
```

**Using Rsync over SSH:**

```bash
rsync -av -e ssh user@<IP>:/remote/path /local/path
rsync -av -e "ssh -p2222" user@<IP>:/remote/path /local/path
```

---

## R-Services (rsh, rlogin, rexec, rcp)
R-Services are legacy Unix remote access tools. They transmit credentials in plaintext over TCP 512–514 and rely on **trusted host files** (`/etc/hosts.equiv` and `.rhosts`).

**Common Commands:**

|Command|Port|Description|
|---|---|---|
|rsh|514|Remote shell|
|rlogin|513|Remote login|
|rexec|512|Execute commands remotely|
|rcp|514|Remote file copy|

**Footprinting R-Services:**

```bash
sudo nmap -sV -p 512,513,514 <IP>
```

**Check trusted hosts:**

```bash
cat /etc/hosts.equiv
cat ~/.rhosts
```

**Remote login using Rlogin:**

```bash
rlogin <IP> -l htb-student
```

**Check logged-in users:**

```bash
rwho
rusers -al <IP>
```
