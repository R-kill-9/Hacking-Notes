**WPScan** is a widely-used open-source security scanner specifically designed to detect vulnerabilities in WordPress websites.

| Option                      | Description                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `--url`                     | Specifies the URL of the WordPress website you want to scan.                                                              |
| `--enumerate`               | Enumerates vulnerable plugins (`vp`), users (`u`), themes (`t`),  version (`v`) and plugins (`p`).                        |
| `--plugins-detection mixed` | Specifies the plugin detection mode, in this case, "mixed," which includes both passive and aggressive detection methods. |
| `--passwords`               | Specifies a file containing a list of passwords to use for brute force attacks.                                           |
| `--usernames`               | Specifies a file containing usernames to use for brute force attacks.                                                     |
| `--exclude-content-length`  | Excludes the Content-Length header from requests.                                                                         |
| `--proxy`                   | Specifies a proxy to use for the scan.                                                                                    |
| `--random-agent`            | Uses a random User-Agent for each request.                                                                                |
| `--verbose`                 | Increases the verbosity level of the output, providing more detailed information about the scan process.                  |

#### Basic usage
```bash
wpscan --url <url>
```

#### Other options
```bash
wpscan --enumerate p,u,t,v 
       --plugins-detection mixed 
       --passwords /path/to/passwords.txt 
       --usernames /path/to/usernames.txt 
       --exclude-content-length 
       --proxy http://proxy.example.com:8080 
       --random-agent 
       --verbose
```
