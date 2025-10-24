**SQLite3** is a lightweight, serverless, self-contained SQL database engine. Unlike other relational databases, SQLite stores the entire database in a single file and does not require a separate server process. It is widely used in mobile apps, embedded systems, and small-scale applications due to its simplicity and portability.


---

## Opening and Exploring SQLite Databases

### Open the database

```bash
sqlite3 database.db
```

### List all tables

```sql
.tables
```

### View schema of a specific table

```sql
.schema table_name
```

### View all data from a table

```sql
SELECT * FROM table_name;
```

### Search with condition

```sql
SELECT * FROM users WHERE age = 30;
```

### Exit SQLite shell

```sql
.exit
```

---

## Useful SQLite Commands

- **List all indexes**:

```sql
.indexes
```

- **List all triggers**:

```sql
SELECT name FROM sqlite_master WHERE type='trigger';
```

- **List all views**:

```sql
SELECT name FROM sqlite_master WHERE type='view';
```

- **Show database info**:

```sql
PRAGMA database_list;
```

- **Show table info**:

```sql
PRAGMA table_info(table_name);
```

- **Dump entire database**:

```sql
.dump
```

