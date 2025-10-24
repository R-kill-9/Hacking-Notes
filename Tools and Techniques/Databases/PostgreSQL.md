**PostgreSQL** is a powerful, open-source object-relational database system known for its robustness, extensibility, and standards compliance. It supports advanced features such as full-text search, custom data types, stored procedures, and JSON querying. PostgreSQL is widely used in enterprise, academic, and web environments.

---

## Detection with Nmap

### Detect PostgreSQL service and version

```bash
nmap -p 5432 --script pgsql-info <target>
```

- Reveals PostgreSQL version and configuration details

### Brute-force PostgreSQL login

```bash
nmap -p 5432 --script pgsql-brute --script-args userdb=users.txt,passdb=pass.txt <target>
```

---
## Connecting Remotely

```bash
psql -h <host> -U <username> -d <database>
```

- `-h`: Host IP or domain
- `-U`: Username
- `-d`: Database name

---


## Starting PostgreSQL Locally (Kali or Linux)

### Start PostgreSQL service

```bash
sudo service postgresql start
```

### Switch to the postgres user

```bash
sudo -i -u postgres
```

### Access PostgreSQL shell

```bash
psql
```

---

## Creating and Importing Databases

### Create a new database

```bash
createdb db_name
```

### Import a SQL dump

```bash
psql -d db_name -f database.sql
```

### Restore a custom-format backup

```bash
pg_restore -d db_name database.backup
```

---

## Common SQL Commands

- **List all databases**:

```sql
\l
```

- **Connect to a database**:

```sql
\c db_name
```

- **List all tables**:

```sql
\dt
```

- **List all users**:

```sql
\du
```

- **Describe a table**:

```sql
\d table_name
```

- **Query all data from a table**:

```sql
SELECT * FROM table_name;
```

- **Search with condition**:

```sql
SELECT * FROM users WHERE email LIKE '%@gmail.com';
```

- **Exit PostgreSQL shell**:

```sql
\q
```


---

## Useful PostgreSQL Commands

- **List schemas**:

```sql
\dn
```

- **List functions**:

```sql
\df
```

- **List roles**:

```sql
SELECT rolname FROM pg_roles;
```

- **Show current user**:

```sql
SELECT current_user;
```

- **Show current database**:

```sql
SELECT current_database();
```

