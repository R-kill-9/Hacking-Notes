**WordPress** is a popular Content Management System (CMS) used to create and manage websites. Due to its widespread use, it is often targeted by attackers.

## Version Detection


- **Meta Tags:** Some WordPress sites expose their version in `<meta name="generator" content="WordPress x.x.x">`. This information is available when inspecting the site's source code.

- **X-Powered-By:** Sometimes this server's response header reveals important information as the Wordpress version in use.

- **RSS Feeds:** `<target_url>/?feed=rss2` WordPress RSS feeds may include version information.

- **Readme.html File:** `https://example.com/readme.html` may reveal the installed WordPress version.

- **WPScan Tool:** `wpscan --url https://example.com --enumerate v`.

## User Enumeration

- **Author Archives:** Adding `?author=1` to a WordPress URL may redirect to `/author/username/`, revealing the username.

- **REST API:** `https://example.com/wp-json/wp/v2/users/` can expose user data if not properly secured.

- **Login Error Messages:** WordPress sometimes reveals if a username exists through login failure messages.

- **WPScan Tool:** `wpscan --url https://example.com --enumerate u` performs automated user enumeration.


## Plugin Enumeration

- **wp-content Directory Listing:** Some servers expose `/wp-content/plugins/` if directory listing is enabled.

- **WPScan Tool:** `wpscan --url https://example.com --enumerate p` scans for installed plugins.

- **Nmap Scripts:** `nmap --script http-wordpress-plugins --script-args wordpress-plugins.basepath=/wp-content/plugins/,http-wordpress-plugins.search-limit=100 example.com`


## Theme Enumeration


- **Direct Access:** Checking `https://example.com/wp-content/themes/theme-name/`.

- **WPScan Tool:** `wpscan --url https://example.com --enumerate t`.

- **WhatWeb Tool:** `whatweb -a 3 https://example.com`.

