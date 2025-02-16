## Nmap
**Nmap** can help identify MySQL service and attempt to get basic information about the MySQL server, including version and potential authentication weaknesses.

```bash
nmap -p 3306 --script mysql-info <target_ip>
```

## Hydra
Brute force attacks can be used to test common or weak usernames and passwords against the MySQL login. 

```bash
hydra -l <username> -P <password_list> mysql://<target_ip>:3306
```

## MySQL Enumeration with Metasploit*
**Metasploit** offers several modules for enumerating MySQL services on a target.

- **Identify MySQL Version**: Use `mysql_version` to identify the version of MySQL running on the target system. 
- **Brute Force MySQL Login**: Use `mysql_login` to perform brute force attacks on MySQL login credentials, testing username and password combinations.
- **Enumerate MySQL Databases, Tables, and Users**: Use `mysql_enum` to enumerate MySQL databases, tables, and users. You will need credentials for this.
- **Execute Custom SQL Queries**: Use `mysql_sql` to run custom SQL queries against the MySQL server. You will need credentials for this.
- **Dump MySQL Database Schema**: Use `mysql_schemadump` to dump the schema of a MySQL database. You will need credentials for this.
- **Dump MySQL Password Hashes**: Use `hashdump` to extract the password hashes from the MySQL database. You need administrative access to the MySQL server to perform this operation.