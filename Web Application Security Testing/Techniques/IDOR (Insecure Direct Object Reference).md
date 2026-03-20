IDOR is an access control vulnerability where the application exposes internal object references (IDs, filenames, keys) and fails to verify whether the user is authorized to access them.

The core issue is not the identifier itself, but the **lack of authorization checks on the server side**.

---

## Basic Concept

This vulnerability appears when user input is directly used to retrieve resources without validation.

For example, the application may take an `id` parameter and use it to query a database:

```http
GET /profile?id=1001
```

If the server does not verify that the logged-in user owns this resource, an attacker can modify the ID:

```http
GET /profile?id=1002
```

If another user's data is returned, the application is vulnerable.


---

## Common Vulnerable Patterns

Applications tend to expose object references in predictable ways. These are the most common patterns.

### Numeric IDs

Many applications use incremental IDs:

```http
GET /api/user/123
GET /api/user/124
```

Since these values are predictable, an attacker can easily enumerate them and access other users' data if authorization is missing.


### File Access

File download functionality is another common case:

```http
GET /download?file=invoice_1001.pdf
```

If the server does not validate ownership, changing the filename may expose other users’ files:

```http
GET /download?file=invoice_1002.pdf
```


### API Endpoints

Modern applications often expose APIs with user identifiers:

```http
GET /api/orders?user_id=45
```

If the backend trusts this parameter, an attacker can simply change it:

```http
GET /api/orders?user_id=46
```



---

## Detection Methodology

The goal is to identify where user input controls access to objects and test whether authorization is enforced.

Start by looking for parameters that reference objects:

- `id`
    
- `user_id`
    
- `account`
    
- `file`
    
- `doc`
    
- `uid`
    

Then attempt to access resources that should belong to other users.


### Manual Testing

Manual testing is the most reliable method to confirm IDOR.

1. Capture a legitimate request:
    

```http
GET /profile?id=1001
Cookie: session=abc123
```

2. Modify the identifier:
    

```http
GET /profile?id=1002
```

3. Analyze the response:
    

- If different user data is returned → vulnerable
    
- If access is denied → properly protected
    

The key is to compare responses and understand what changes.


### Automated Enumeration (ffuf)

You can automate testing by fuzzing identifiers.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
-u "http://target/profile?id=FUZZ" \
-H "Cookie: session=abc123" \
-fs 1234
```

This sends multiple requests replacing `FUZZ` with values from the wordlist.

`-fs` filters responses with the same size, helping you quickly identify interesting differences.


### Using Burp Intruder

Burp Intruder allows controlled fuzzing of parameters.

- Select the parameter (`id`)
    
- Use numeric payloads or custom lists
    
- Analyze:
    
    - response length
        
    - status codes
        
    - differences in content
        

This is useful when responses are subtle and not obvious.

---

## Types of IDOR

Different types of IDOR depend on what level of access is gained.

### Horizontal Privilege Escalation

This happens when you access resources belonging to another user at the same privilege level.

```http
GET /api/user?id=2002
```

You are not increasing privileges, but accessing someone else’s data.

### Vertical Privilege Escalation

This occurs when you access resources belonging to higher privilege users (e.g., admins).

```http
GET /admin/panel?id=1
```

If accessible, this may lead to full compromise of the application.

### Direct File Access

Sometimes files are stored in predictable paths:

```http
GET /uploads/user123/report.pdf
```

If directory structure is predictable, you can try:

```http
GET /uploads/user124/report.pdf
```

This often leads to sensitive file disclosure.

---
Perfecto, aquí tienes la sección **Advanced Cases** rehacida con más claridad técnica y mejor explicación:

---

## Advanced Cases

Not all IDOR vulnerabilities rely on simple numeric identifiers. In many real applications, developers try to “hide” object references using encoding, hashing, or random identifiers. However, these mechanisms do not fix the core issue if authorization is still missing.

The key idea is that **obfuscation is not access control**.

### UUID-based IDs

Some applications replace incremental IDs with UUIDs:

```http
GET /api/user/550e8400-e29b-41d4-a716-446655440000
```

These values are not predictable, which prevents simple brute-force enumeration.

However, they are still vulnerable if:

- UUIDs are leaked in responses (e.g., API responses, HTML, JavaScript)
    
- Users can access objects by directly supplying a valid UUID
    

Once a single valid UUID is obtained, it can be reused to access the same resource without authorization checks.


### Encoded IDs

Applications sometimes encode identifiers (e.g., Base64) to make them less obvious:

```http
GET /profile?id=MQ==
```

Decoding:

```bash
echo MQ== | base64 -d
```

This reveals the original value (`1` in this case).

Encoding does not protect against IDOR because:

- It is reversible
    
- The server still trusts the decoded value without validation
    

An attacker can decode, modify, and re-encode values to access other resources.


### Hashed IDs

Some applications use hashes instead of raw IDs:

```http
GET /profile?id=5f4dcc3b5aa765d61d8327deb882cf99
```

This may look secure, but it depends on how the hash is generated.

Common issues:

- Hashes based on predictable values (e.g., `md5(user_id)`)
    
- No salt or weak hashing logic
    
- Same hash reused across requests
    

If the attacker can understand or reproduce the hashing logic, they can generate valid identifiers for other users.

