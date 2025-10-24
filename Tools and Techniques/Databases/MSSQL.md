**Microsoft SQL Server (MSSQL)** is a relational database management system developed by Microsoft. It is widely used in enterprise environments for storing and managing structured data. MSSQL supports powerful querying capabilities through Transact-SQL (T-SQL), and it can be accessed remotely over the network using TCP port **1433** by default.

---

## Enumerating MSSQL with Nmap

### Scan for MSSQL Service and Scripts

```bash
nmap -p 1433 --script ms-sql-info <target>
```

- Detects MSSQL version and configuration

### Brute Force SQL Authentication

```bash
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt <target>
```

- Attempts to brute-force login credentials


---

## Connecting to MSSQL from Kali Linux
### Using mssqlclient.py from Impacket

```bash
python3 mssqlclient.py <username>:<password>@<host> 
```

- Supports both SQL and Windows authentication
- Useful for enumeration and command execution if xp_cmdshell is enabled



### Using sqlcmd 

```bash
sqlcmd -S <host> -U <username> -P <password>
```

- `-S`: Server address
- `-U`: Username
- `-P`: Password

Once connected, you can run T-SQL commands interactively.


---

## Common T-SQL Commands

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

## Importing or Restoring MSSQL Databases

If you have a `.bak` file (backup), you can restore it using SQL Server Management Studio (SSMS) or T-SQL:

```sql
RESTORE DATABASE [db_name]
FROM DISK = 'C:\path\to\backup.bak'
WITH MOVE 'db_name_Data' TO 'C:\MSSQL\Data\db_name.mdf',
MOVE 'db_name_Log' TO 'C:\MSSQL\Data\db_name.ldf';
```

