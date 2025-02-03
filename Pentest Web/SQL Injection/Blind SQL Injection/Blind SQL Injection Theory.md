**Blind SQL Injection** is a type of SQL injection attack where the direct result of the query is not visible. No error messages or data are returned; instead, the behavior of the application is used to infer the outcome of the query. This method is used when the application does not show database errors, but the application's responses still reveal important information.

Blind SQL Injection is typically classified into two main types:

1. **Boolean-based Blind SQL Injection**
2. **Time-based Blind SQL Injection**

---

## Boolean-Based Blind SQL Injection

In **Boolean-based Blind SQL Injection**, the query is modified with a conditional statement that evaluates to either true or false. Based on the application's response (e.g., whether the page loads normally or not), it's possible to infer certain details about the database.

#### How It Works

A conditional SQL statement is added to the query to check if a condition is true or false.

- **True Condition (True Response):** The page will load or behave normally.
- **False Condition (False Response):** The page might load differently, display an error, or not load at all.

#### Example

Consider the original URL:
```bash
http://example.com/page?id=1
```
Injecting a true condition:
```bash
http://example.com/page?id=1 AND 1=1
```

This query evaluates as true, so the page loads normally.

Injecting a false condition:
```bash
http://example.com/page?id=1 AND 1=2
```

This query evaluates as false, and the page might behave differently (e.g., not load, show an error, etc.).

By testing various conditions, it becomes possible to determine details such as the existence of specific tables or data in the database.

---

### Time-Based Blind SQL Injection

**Time-based Blind SQL Injection** involves introducing a time delay into the query. The response time of the server is used to infer whether a condition is true or false. A delay function (e.g., `SLEEP()` or `DBMS_LOCK.sleep()`) is injected into the query to intentionally pause the server’s response.

#### How It Works

- A time delay function like `SLEEP()` or `DBMS_LOCK.sleep()` is added to the query.
- If the condition evaluates as true, the server introduces a delay in the response.
- If the condition evaluates as false, there is no delay in the response.

#### Example

For **MySQL**, the query might look like this:
```bash
http://example.com/page?id=1 AND SLEEP(5)
```

If the page responds after 5 seconds, the condition is true. If there is no delay, the condition is false.

In **Oracle**, the equivalent query might look like:
```bash
http://example.com/page?id=1 AND DBMS_LOCK.sleep(5)
```



---



## Functions to Use in Blind SQL Injection

#### MySQL Functions

1. **`SLEEP(seconds)`**
This function is used to introduce a time delay in the server's response. When used in a time-based blind SQL injection, it helps determine whether a condition is true or false by delaying the response when the condition is met. 

```bash
http://example.com/page?id=1 AND SLEEP(5)
```

2. **`SUBSTRING(string, start, length)`**
This function allows for extracting a portion of a string from a given starting position and length. It is useful for extracting specific characters from database columns.

```bash
http://example.com/page?id=1 AND SUBSTRING(username, 1, 1) = 'a'
```

3. **`CHAR()`** 
Converts a numeric value to its corresponding character.

```bash
SELECT CHAR(65); -- returns 'A' since 65 is the ASCII value for 'A'
```


#### Oracle Functions

1. **`DBMS_LOCK.sleep(seconds)`**
Similar to MySQL's `SLEEP()` function, this function introduces a time delay in Oracle databases. 

```bash
http://example.com/page?id=1 AND DBMS_LOCK.sleep(5)
```

2. **`SUBSTR(string, start, length)`**
This Oracle function is equivalent to MySQL's `SUBSTRING()` function. It allows the extraction of a portion of a string,.

```bash
http://example.com/page?id=1 AND SUBSTR(username, 1, 1) = 'a'
```

