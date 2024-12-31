**SearchSploit** is used to search and locate known exploits and vulnerabilities in a wide variety of software and systems. It utilizes the Exploit Database, which contains an extensive collection of exploits, shellcodes, and security-related references.
```bash
searchsploit <whatever>
```

Once we find the exploit that we need we can know the path where it's stored with the command:

```bash
searchsploit -p <exploit_number>
```

Also, we can copy the exploit to our current directory using the `-m` option.

```bash
searchsploit -m <exploit_number>
```