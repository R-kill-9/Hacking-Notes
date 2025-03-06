**Fuzzing** is an automated software testing method that injects invalid, malformed, or unexpected inputs into a system to reveal software defects and vulnerabilities. A fuzzing tool injects these inputs into the system and then monitors for exceptions such as crashes or information leakage.

## Feroxbuster

Feroxbuster is a **fast, recursive, and parallel** directory and file brute-forcing tool written in Rust. It is highly effective for finding hidden directories and files.

#### Basic Usage

```
feroxbuster -u <URL>
```

#### Useful Parameters

|   |   |
|---|---|
|Option|Description|
|`-u <URL>`|Target URL to scan.|
|`-w <wordlist>`|Specify a custom wordlist.|
|`-t <threads>`|Number of threads to use (default: 50).|
|`-n`|Do not recurse into found directories.|
|`-e`|Extensions to fuzz (e.g., `-e php,txt,html`).|
|`-x <extensions>`|Filter results by file extension.|
|`-o <file>`|Output results to a file.|

#### Example Usage:

- **Basic scan:**
```
feroxbuster -u http://<machine-ip> -t 50
```

- **Recursive scan with a wordlist:**
```
feroxbuster -u http://<machine-ip> -w <wordlist> -r
```

- **Scan for specific extensions:**
```
feroxbuster -u http://<machine-ip> -e php,html,txt
```

- **Save results to a file:**
```
feroxbuster -u http://<machine-ip> -o results.txt
```




---


## Gobuster
It is a command-line tool used for performing brute-force scans or directory and subdomain enumeration on a website.
- To find subdirectories:
````bash
#wordlist example:/usr/share/wordlists/dirb/big.txt
#wordlist example: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
#machine example: 10.10.192.23 or http://10.10.192.23:80
#-q to don't print the errors
gobuster dir -u <machine-ip> -w <wordlist> -o gobuster.out -t 200
````

- To find subdomains:
```bash
#wordlist example: /usr/share/dnsrecon/subdomains-top1mil-20000.txt
#machine ip example: 10.10.192.25
gobuster vhost -w <wordlist> -u <machine-ip> -o gobuster.out
````



---



## wfuzz
It is a command-line tool used for performing brute-force scans or directory and subdomain enumeration on a website. Also, it can be useful for enumerate files with an specific extension.
#### Useful parameters
| Option | Description                                                                         |
| ------ | ----------------------------------------------------------------------------------- |
| `--hc` | This filter excludes responses that have x words.                                   |
| `--hl` | This filter excludes responses that have x lines, which seem to be false positives. |
| `--hh` | This filter excludes responses that have x characters.                              |

#### Subdomains
```bash
#wordlist example:/usr/share/wordlists/dirb/big.txt
#machine example: 10.10.192.23
#-c print with colours
#--hc <status> don't print outuput with this status. For example: --hc 404
wfuzz -c  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt  -u http://<machine-ip> -H "Host: FUZZ.<machine-ip>" -t 100
```


#### Subdirectories
```bash
#wordlist example:/usr/share/wordlists/dirb/big.txt
#machine example: 10.10.192.23
#-c print with colours
#--hc 404 don't print errors
wfuzz -c --hc 404 -w <wordlist> http://<machine-ip>/FUZZ
```

#### Common files
```bash
#wordlist example:/usr/share/wordlists/dirb/big.txt
#machine example: 10.10.192.23
#-c print with colours
#--hc 404 don't print errors
wfuzz -c --hc 404 -w <wordlist> http://<machine-ip>/FUZZ.php
```



---





## ffuf
Fuff is primarily used for discovering hidden resources in web applications by brute-forcing URLs and parameters. It is effective for testing web application security, identifying vulnerabilities, and mapping application structures.

#### Basic Usage

Fuff operates from the command line. The basic syntax for using Fuff is as follows:
```bash
ffuf -u <URL> -w <wordlist>
```
- **Parameters**:
    - `-u <URL>`: Target URL (with optional parameters).
    - `-w <wordlist>`: Path to the wordlist for fuzzing.

#### Post method

```bash
# request_file = request to fuzz saved from Burpsuite
ffuf -u <URL> -X POST -request <request_file> -w <wordlist> -fs 61
```

#### Common Options

| Option              | Description                                                               |
| ------------------- | ------------------------------------------------------------------------- |
| `-r`                | Set the request method (GET, POST, etc.).                                 |
| `-t <number>`       | Set the number of concurrent threads (default is 10).                     |
| `-mc <status_code>` | Match responses with specific status codes (e.g., 200, 404).              |
| `-o <output_file>`  | Save the output to a specified file.                                      |
| `-p <parameter>`    | Specify a parameter for fuzzing.                                          |
| `-d <parameter>`    | Defines the data that will be sent in the body of a POST request.         |
| `-fs 61`            | Filters responses by size (e.g., filter responses based on their length). |
