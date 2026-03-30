Stacked queries allow the execution of **multiple SQL statements in a single request**, typically separated by `;`.  
This changes the nature of the vulnerability: instead of just manipulating a query result, you can **execute additional queries with side effects**.

This makes stacked SQLi one of the most powerful forms, especially in DBMS like MSSQL and PostgreSQL.

---

## Detection approach

The objective is to determine whether the backend:

- accepts multiple statements
    
- executes them sequentially
    
- does not sanitize or block the separator
    

Unlike other SQLi types, detection relies heavily on **side effects**, not direct output.

### Basic probing

You start by attempting to append a second query.

```
GET /endpoint?param=10;SELECT 1 HTTP/1.1
```

If the application:

- throws a different error
    
- behaves differently than baseline
    

it may indicate that the second query is being parsed.

However, this alone is not enough. Many backends will reject stacked queries silently.

### Error-based confirmation

A reliable way to confirm execution is to force an error in the second query.

```
GET /endpoint?param=10;SELECT 1/0 HTTP/1.1
```

If you observe:

- division by zero error
    
- generic SQL error triggered only with this payload
    

then the second query is being executed.

This is one of the clearest confirmations.


### Time-based confirmation

This is the most reliable method when no output is visible.

```
GET /endpoint?param=10;WAITFOR DELAY '0:0:5'-- HTTP/1.1
```

or

```
GET /endpoint?param=10;SELECT pg_sleep(5)-- HTTP/1.1
```

If the response is consistently delayed:

- stacking is supported
    
- second query is executed independently
    

Always validate against baseline latency and repeat multiple times.

---

## Exploitation methodology

Once stacking is confirmed, the attack surface expands from **read-only** to **read-write-execute**.

You can now inject queries that:

- modify data
    
- insert new records
    
- trigger system-level features
    


### Data modification

You can directly alter database content.

```
GET /endpoint?param=10;UPDATE users SET role='admin' WHERE username='user'-- HTTP/1.1
```

This is typically used for:

- privilege escalation
    
- account takeover
    


### Data insertion

You can create new entities inside the application.

```
GET /endpoint?param=10;INSERT INTO users (username,password) VALUES ('attacker','hash')-- HTTP/1.1
```

This is useful for persistence without breaking existing accounts.


### Leveraging DBMS features

Stacked queries become critical when the DBMS exposes dangerous functionality.

#### MSSQL example

```
GET /endpoint?param=10;EXEC xp_cmdshell 'whoami'-- HTTP/1.1
```

If enabled, this allows:

- command execution on the host
    
- full system compromise
    


#### PostgreSQL example

```
GET /endpoint?param=10;COPY (SELECT '') TO PROGRAM 'id'-- HTTP/1.1
```

This can lead to command execution depending on configuration.


### Blind extraction using stacking

Even without visible output, stacking allows combining logic with delays.

```
GET /endpoint?param=10;IF (SUBSTRING(DB_NAME(),1,1)='a') WAITFOR DELAY '0:0:5'-- HTTP/1.1
```

This effectively turns stacked queries into a **time-based extraction channel**.

---

## Limitations and real-world constraints

Stacked queries are often unavailable due to:

- database connectors disabling multiple statements
    
- ORM protections
    
- prepared statements
    
- WAF filtering of `;`
    

For example:

- MySQL in web apps often disables stacking by default
    
- MSSQL environments are more commonly vulnerable
    

Because of this, you should always:

- test explicitly
    
- never assume availability
    

---

## Integration with sqlmap

Sqlmap can detect and exploit stacked queries, but it is important to guide it.

```
sqlmap -u "http://target/endpoint?param=10" -p param --technique=S
```

Once confirmed, you can move to advanced exploitation:

```
sqlmap -u "http://target/endpoint?param=10" -p param --os-shell
```

Stacked queries are often used internally by sqlmap to achieve:

- command execution
    
- file system access
    
- privilege escalation
    
