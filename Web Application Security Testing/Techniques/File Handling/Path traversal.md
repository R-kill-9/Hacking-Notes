This attack typically takes advantage of insufficient input validation or sanitization mechanisms. By manipulating the input, an attacker can traverse directories and access sensitive files that should not be directly accessible. This could include system files, configuration files, or even user data.

For example, if a web application allows users to download files by specifying a file name in the URL, an attacker could provide a malicious input such as "../../../etc/passwd" to traverse up the directory tree and access the password file.

That can be useful if, for example, the web has a php file with a variable called `filename`.
In this case, we could make a request attempting to access other files, such as /etc/passwd.

```bash
http://example.com/?filename=../../../../../../etc/passwd
```
In some cases the php code can be blocking this attack switching "../" with "". In this case we could try to do:
```bash
http://example.com/?....//....//....//....//....//etc/passwd
```
Sometimes, if the previous method doesn't work, it can be useful to URL-encode the request or URL-encode it twice.
```bash
..%25df..%25df..%25df..%25df..%25df..%25df..%25df..%25dfetc/passwd
```