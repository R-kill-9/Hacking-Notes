**Fuzzing** is an automated software testing method that injects invalid, malformed, or unexpected inputs into a system to reveal software defects and vulnerabilities. A fuzzing tool injects these inputs into the system and then monitors for exceptions such as crashes or information leakage.

## Feroxbuster

Feroxbuster is a **fast, recursive, and parallel** directory and file brute-forcing tool written in Rust. It is highly effective for finding hidden directories and files.

#### Basic Usage

| Option            | Description                                   |
| ----------------- | --------------------------------------------- |
| `-u <URL>`        | Target URL to scan.                           |
| `-w <wordlist>`   | Specify a custom wordlist.                    |
| `-t <threads>`    | Number of threads to use (default: 50).       |
| `-n`              | Do not recurse into found directories.        |
| `-x <extensions>` | Extensions to fuzz (e.g., `-e php,txt,html`). |
| `-o <file>`       | Output results to a file.                     |


```
feroxbuster -u <URL>
```

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
feroxbuster -u http://<machine-ip> -x php,html,txt
```

- **Save results to a file:**
```
feroxbuster -u http://<machine-ip> -o results.txt
```




---


## Gobuster
It is a command-line tool used for performing brute-force scans or directory and subdomain enumeration on a website.

| Option  | Description                                            |
|---------|--------------------------------------------------------|
| `-u`    | Target URL (e.g., http://10.10.192.23)                 |
| `-w`    | Wordlist path (e.g., /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt) |
| `-o`    | Save results to a file (e.g., gobuster.out)            |
| `-t`    | Number of threads (higher = faster, but more resource-heavy) |
| `-q`    | Quiet mode (suppress error messages)                   |
| `-s`    | Filter response status codes (e.g., `-s 200,403` to show only 200 and 403 responses) |
| `-x`    | Filter by file extensions (e.g., `-x .php,.html`)      |
| `-l`    | Limit results by minimum response length (e.g., `-l 100` to only show responses with length > 100 bytes) |

#### Directory Discovery
Used to find hidden folders and files.
```bash
gobuster dir -u <machine-ip> -w <wordlist> -o gobuster.out -t 200
```

#### Subdomain Enumeration

You can find subdomains in two ways:

1. **VHOST Mode (Virtual Host)**

Used when testing against an IP and expecting subdomains to resolve through the Host header.

```bash
gobuster vhost -u http://<ip> -w <wordlist> -o gobuster.out
```

2. **DNS Mode**

Used when you know the domain name (e.g., medusa.hmv).

```bash
gobuster dns -d <domain> -w <wordlist> -o gobuster.out
```

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

| Option              | Description                                                       |
| ------------------- | ----------------------------------------------------------------- |
| `-u <URL>`          | Target URL.                                                       |
| `-w <wordlist>`     | Path to the wordlist for fuzzing.                                 |
| `-r`                | Set the request method (GET, POST, etc.).                         |
| `-t <number>`       | Set the number of concurrent threads (default is 10).             |
| `-mc <status_code>` | Match responses with specific status codes (e.g., 200, 404).      |
| `-o <output_file>`  | Save the output to a specified file.                              |
| `-p <parameter>`    | Specify a parameter for fuzzing.                                  |
| `-d <parameter>`    | Defines the data that will be sent in the body of a POST request. |
| `-fs <length>`      | Filter out responses by response size (in bytes).                 |
| `-fw <words>`       | Filter by word count.                                             |
| `-fl <lines>`       | Filter by line count.                                             |

```bash
ffuf -u <URL> -w <wordlist>
```


#### Post method

```bash
ffuf -u <URL> -X POST -d "parameter+FUZZ" -w <wordlist> -fs 61
```
