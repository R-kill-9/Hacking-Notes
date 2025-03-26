**WordPress** is a popular Content Management System (CMS) used to create and manage websites. Due to its widespread use, it is often targeted by attackers.

## Version Detection


- **Meta Tags:** Some WordPress sites expose their version in `<meta name="generator" content="WordPress x.x.x">`. This information is available when inspecting the site's source code.

- **X-Powered-By:** Sometimes this server's response header reveals important information as the Wordpress version in use.

- **RSS Feeds:** `<target_url>/?feed=rss2` WordPress RSS feeds may include version information.

- **Readme.html File:** `https://<target>/readme.html` may reveal the installed WordPress version.

- **WPScan Tool:** `wpscan --url https://<target> --enumerate v`.

## User Enumeration

- **Author Archives:** Adding `?author=1` to a WordPress URL may redirect to `/author/username/`, revealing the username.

- **REST API:** `https://<target>/wp-json/wp/v2/users/` can expose user data if not properly secured.

- **Login Error Messages:** WordPress sometimes reveals if a username exists through login failure messages.

- **WPScan Tool:** `wpscan --url https://<target> --enumerate u` performs automated user enumeration.


## Plugin Enumeration

- **wp-content Directory Listing:** Some servers expose `/wp-content/plugins/` if directory listing is enabled.

- **WPScan Tool:** `wpscan --url https://<target> --enumerate p` scans for installed plugins.

- **Nmap Scripts:** `nmap --script http-wordpress-enum --script-args= type="plugins" <target_url>`


## Theme Enumeration


- **Direct Access:** Checking `https://<target>/wp-content/themes/`.

- **WPScan Tool:** `wpscan --url https://<target> --enumerate t`.

- **WhatWeb Tool:** `whatweb -a 3 https://<target>`.

## Files

- **wp-config.php**: Contains database credentials and security keys.

- **.htaccess**: Defines rules for URL redirection, security restrictions, and more.

- **error_log**: May contain error messages that reveal sensitive information.

- **wp-login.php**: Handles WordPress authentication.

- **xmlrpc.php**: Can be exploited for brute-force attacks and DDoS.

- **robots.txt**: Specifies which parts of the site should not be crawled by search engines but may reveal sensitive directories.


## Directories

- **wp-content/**: Stores themes, plugins and media files.

- **wp-includes/**: Contains core WordPress functionality.

- **wp-admin/**: The backend dashboard where administrators manage the site.

- **uploads/**: Stores media files uploaded to the site.

- **themes/**: Holds installed WordPress themes.

- **plugins/**: Stores installed WordPress plugins.

- **logs/**: May contain server or application logs that could leak sensitive information.

