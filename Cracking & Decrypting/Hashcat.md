**Hashcat** is a high-performance password recovery tool that supports a broad set of hash algorithms and multiple attack modes. It can process single hashes or large hash lists from files, and it supports CPU and GPU acceleration. Hashcat is commonly used for legitimate security testing, password auditing, and recovery of lost credentials. Always obtain explicit authorization before attempting to crack any credentials that you do not own.

## Common attack modes and option descriptions

| Option             | Description                                                                                                                                                                                  |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-a 0`             | **Dictionary attack.** Hashcat reads candidate words from a wordlist and applies them directly (optionally with rule presets). Most efficient when a good wordlist exists.                   |
| `-a 1`             | **Combinator attack.** Combines words from two dictionaries (left and right), useful for compound passwords (e.g., `word1word2`).                                                            |
| `-a 3`             | **Mask attack (brute-force with mask).** Uses a mask to specify character sets and lengths (e.g., `?l?l?l?d?d`). Supports incremental mode and is efficient for structured password formats. |
| `-a 6`             | **Hybrid wordlist + mask (wordlist-left, mask-right).** Appends mask-generated suffixes to words from a wordlist.                                                                            |
| `-a 7`             | **Hybrid mask + wordlist (mask-left, wordlist-right).** Prepends mask-generated prefixes to words from a wordlist.                                                                           |
| `-m <mode>`        | **Hash type mode.** Selects the hash algorithm (see hash-mode table below).                                                                                                                  |
| `--username`       | Treat the first field of each line in the hashfile as username and separate it from the hash. Required when you supply `user:hash` style entries.                                            |
| `-r <rulefile>`    | Apply a ruleset to each candidate from the dictionary (modifies or extends words on the fly).                                                                                                |
| `-O`               | Use optimized kernel (may reduce supported maximum password length but improves speed).                                                                                                      |
| `-w <level>`       | Workload profile (1..4). Higher values increase GPU utilization.                                                                                                                             |
| `--status`         | Periodically print status to console.                                                                                                                                                        |
| `--session <name>` | Assign a session name; useful to pause/resume runs.                                                                                                                                          |
| `-o` / `--outfile` | Output file for cracked passwords.                                                                                                                                                           |
| `--potfile-path`   | Path to potfile (where cracked hashes are recorded).                                                                                                                                         |
| `--increment`      | Enable incremental mode with `-a 3` to test progressively larger password lengths.                                                                                                           |
| `--force`          | Force execution despite warnings (use with caution).                                                                                                                                         |
#### Basic Usage
```bash
# save hashes in hashes.txt, wordlist is /usr/share/wordlists/rockyou.txt
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```


---

## Dictionaries and rulesets 

#### Kaonashi + haku34 rules

- **Repository:** `https://github.com/kaonashi-passwords/Kaonashi`

- **Notes:** Kaonashi dictionaries are large, leak-derived wordlists that tend to yield high success rates compared to smaller, older lists (e.g., rockyou). The `haku34` ruleset is an aggressive, high-coverage set of transformation rules used in some cracking projects (RootedCON 2019).

- **Usage guidance:** Use Kaonashi + `haku34` for fast hashes (NTLM, MD5, etc.) when GPU time is available. For long-running jobs or when GPU memory/time is limited, consider using a less aggressive ruleset (e.g., `yubaba64` or a smaller rule file) to reduce runtime and candidate explosion.

#### Lemario (Spanish) + OneRuleToRuleThemAll

- **Repository:** `https://github.com/olea/lemarios` (lemario-general-del-espanol.txt)

- **Notes:** Comprehensive Spanish-language wordlist. Combine with `OneRuleToRuleThemAll.rule` for broad morphological coverage and high likelihood to hit Spanish-language passwords.


---

## Mask-based strategies

 Mask attacks are incremental and are ideal for structured or partially-known formats (e.g., DNI, years, known prefixes).

- Example: brute force up to 7 characters (any character set), incremental:
```bash
hashcat -a 3 -m 1000 hash.txt --increment --force -O -w 4 "?a?a?a?a?a?a?a"
```

- Example with a custom class combining lower+upper for last character:
```bash
hashcat -a 3 -m 1000 -O -w 4 -1 ?l?u ntds.txt ?d?d?d?d?d?d?d?d?1
```


---
## Hashcat modes

|Hash mode (`-m`)|Algorithm name|
|---|---|
|0|MD5|
|100|SHA1|
|1400|SHA256|
|1700|SHA-512|
|500|md5crypt (MD5 (Unix))|
|400|phpass (WordPress / Joomla MD5)|
|300|MySQL4.1 / MySQL5|
|900|MD4|
|1000|NTLM|
|2100|DCC2 / MS-Cache v2|
|2500|WPA-EAPOL-PBKDF2 (WPA/WPA2)|
|3000|LM (LAN Manager)|
|3200|bcrypt|
