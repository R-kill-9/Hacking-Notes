

**Kerbrute** is a fast and flexible Kerberos pre-auth bruteforcer written in Go. It is commonly used for user enumeration and password spraying in Active Directory environments. It interacts directly with the KDC (Kerberos) over UDP/TCP (port 88).


---

## Key features

- User enumeration: detect valid usernames via Kerberos error responses.
- Password spraying: test a single password against many users.
- Brute force: test username:password combos or a single user with a wordlist.
- Multithreading: concurrent requests (default 10 threads, adjustable).
- No domain join required: works without being part of the domain.
- Safe mode: optional behavior to stop when accounts lock out.


---

## Installation 

1. Go to the Kerbrute releases page and download the appropriate binary for your OS/architecture (e.g. `kerbrute_linux_amd64`).
    
2. Make it executable and move to a directory in your PATH:


```bash
chmod +x kerbrute_linux_amd64
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```


----


## Usage 

1. User enumeration

```bash
kerbrute userenum -d example.local --dc 192.168.1.10 users.txt
```

2. Password spraying (single password against a list of users)

```bash
kerbrute passwordspray -d example.local --dc 192.168.1.10 users.txt password123
```

3. Single-user brute force from a wordlist

```bash
kerbrute bruteuser -d example.local --dc 192.168.1.10 passwords.lst targetuser
```

4. Brute-force username:password combos (file or stdin)

```bash
# from file (format username:password)
kerbrute bruteforce -d example.local --dc 192.168.1.10 combos.txt

# from stdin
cat combos.txt | kerbrute -d example.local --dc 192.168.1.10 bruteforce -
```

#### Common flags

- `-d, --domain` string : domain (e.g. contoso.com)
    
- `--dc` string : Domain Controller / KDC address (if omitted, KDC is resolved via DNS)
    
- `-t` int : number of threads (default 10)
    
- `-o` string : log file (write output to file)
    
- `-v` : verbose (log failures)
    
- `--delay` int : delay in milliseconds between attempts (forces single-threaded)
    
- `--safe` : stop when an account is reported locked out
    
- `--downgrade` : force downgraded encryption type (arcfour-hmac-md5)
    
- `--hash-file` string : file to save captured AS-REP hashes
