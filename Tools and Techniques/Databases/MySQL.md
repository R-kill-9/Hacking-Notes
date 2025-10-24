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



