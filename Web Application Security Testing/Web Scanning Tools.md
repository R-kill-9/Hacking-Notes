## Nikto
**Nikto** is an open-source web server scanner that identifies security vulnerabilities, outdated software, and misconfigurations. It is commonly used in penetration testing to analyze web servers, virtual hosts, and applications.

- **Scans for 6,700+ vulnerabilities**, including outdated software and misconfigurations.  
- **Checks for default files and insecure HTTP headers**.  
- **Supports SSL/TLS scanning** to detect weak encryption.  
- **Finds directory indexing and sensitive files**.  
- **Can use proxies and custom headers** for stealth scanning.

#### Parameters

| Option                      | Description                                              |
| --------------------------- | -------------------------------------------------------- |
| **`-h`** `<host>`           | Specifies the **target host/IP** (mandatory).            |
| **`-p`** `<port>`           | Specifies a **port** (default is 80).                    |
| **`-ssl`**                  | Forces an **SSL/TLS connection** (useful for HTTPS).     |
| **`-Tuning`** `<options>`   | Selects **specific tests** (e.g., XSS, SQLi, RFI).       |
| **`-o`** `<file>`           | Saves output to a **file**.                              |
| **`-Format`** `<type>`      | Sets the **output format** (e.g., txt, XML, HTML, JSON). |
| **`-update`**               | Updates Nikto’s vulnerability database.                  |
| **`-useproxy`** `<proxy>`   | Uses a **proxy** for scanning (stealth mode).            |
| **`-timeout`** `<seconds>`  | Sets a **timeout** for requests.                         |
| **`-useragent`** `<string>` | Changes the **User-Agent** to evade detection.           |
```bash
nikto -h <url>
```

Save Output to a File (JSON Format):

```bash
nikto -h <url> -o results.json -Format json
```



---


## Nuclei
**Nuclei** is a vulnerability scanner that can be used to identify and exploit vulnerabilities in web applications and other services.
It can be used to identify a wide range of vulnerabilities, including:

- **Injection vulnerabilities:** These vulnerabilities allow an attacker to inject malicious code into a target application.
- **Cross-site scripting (XSS) vulnerabilities:** These vulnerabilities allow an attacker to inject malicious code into a web page that is then executed by a victim's browser.
- **SQL injection vulnerabilities:** These vulnerabilities allow an attacker to inject malicious SQL code into a web application, which can then be used to steal data or gain unauthorized access.
- **Authentication vulnerabilities:** These vulnerabilities allow an attacker to bypass authentication and gain unauthorized access to a system.

#### Parameters
| Option                  | Description                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------- |
| `-target / -u`          | Allows indicating a URL on which the tests will be performed.                         |
| `-list / -l`            | Allows indicating a list of targets in a text file, one URL per line in the file.     |
| `-automatic-scan / -as` | Executes an automatic scan using Wappalyzer to detect the architecture of the target. |
| `-templates / -t`       | List of templates or directories containing templates separated by commas.            |

```bash
# url example: http://192.1689.199.45/login.php
nuclei -u <url> 
# you can filter for the severity
nuclei -u <url> -severity high,critical -o output.txt
```


