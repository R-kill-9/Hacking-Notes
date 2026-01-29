**MongoDB** is a popular open-source **NoSQL** database designed for high performance, scalability, and flexibility. Unlike traditional relational databases, MongoDB stores data in **JSON-like documents** (BSON format), making it ideal for applications with dynamic or hierarchical data structures. It is widely used in modern web development, especially with Node.js and MERN stack applications.

---

## Detection with Nmap

### Detect MongoDB service and version

```bash
nmap -p 27017 --script mongodb-info <target>
```

- Reveals MongoDB version and basic configuration

### Brute-force MongoDB login

```bash
nmap -p 27017 --script mongodb-brute --script-args userdb=users.txt,passdb=pass.txt <target>
```

- Attempts to guess valid credentials

---

## Connecting Remotely

```bash
mongosh "mongodb://<username>:<password>@<host>:27017"
```

- Replace `<host>` with IP or domain
- Use `--authenticationDatabase admin` if needed

---


## Starting MongoDB Locally (Kali or Linux)

### Start MongoDB service

```bash
sudo service mongod start
```

### Access MongoDB shell

```bash
mongosh
```

If using the legacy shell:

```bash
mongo
```

---

## Basic MongoDB Shell Commands

### List all databases

```javascript
show dbs
```

### Switch to a database

```javascript
use <db_name>
```

### List all collections in current database

```javascript
show collections
```

### Query all documents in a collection

```javascript
db.collection_name.find()
```

### Query with condition

```javascript
db.users.find({ age: 30 })
```

### Insert a document

```javascript
db.users.insertOne({ name: "Alice", age: 25 })
```

### Update a document

```javascript
db.users.updateOne({ name: "Alice" }, { $set: { age: 26 } })
```

### Delete a document

```javascript
db.users.deleteOne({ name: "Alice" })
```

---

## Useful MongoDB Shell Commands

- **Show current database**:

```javascript
db
```

- **Count documents in a collection**:

```javascript
db.collection_name.countDocuments()
```

- **Get indexes**:

```javascript
db.collection_name.getIndexes()
```

- **Export collection to JSON**:

```bash
mongoexport --db <db_name> --collection <collection_name> --out data.json
```

- **Import JSON to collection**:

```bash
mongoimport --db <db_name> --collection <collection_name> --file data.json
```

