When testing an Android app on a rooted device or emulator, it is often useful to inspect files created during execution. These may include **Shared Preferences**, **SQLite databases**, or other internal storage files.

---

#### Accessing the App's Data Directory

Location of app data:
```bash
/data/data/<package_name>/
```

How to access:
```bash
adb shell
su
cd /data/data/<package_name>/
```

_Note:_ Root privileges (`su`) are required to access this path.

---

####  Examining Shared Preferences

Shared Preferences files are XML format and stored under:
```bash
/data/data/<package_name>/shared_prefs/
```

To list and read preference files:
```bash
cd shared_prefs
ls -l
cat <preference_file>.xml
```

_Typical use:_ Shared prefs store sensitive configuration such as tokens, flags, or credentials.

---

####  Interacting with SQLite Databases

SQLite databases are stored in:
```bash
/data/data/<package_name>/databases/
```

To analyze:
```bash
cd databases
ls -l
sqlite3 <database_name>.db
```

Inside the SQLite shell:
```bash
.tables;        -- List tables
.schema <table>; -- Show schema of a table
SELECT * FROM <table>; -- Dump all rows
.exit
```


---

#### Identifying Recently Created or Modified Files

To detect runtime-generated files or modifications:
```bash
ls -lt
```
This lists files sorted by modification time, with the newest first.

Alternatively, monitor directory changes in real-time using:

```bash
while true; do ls -lt; sleep 5; done
```