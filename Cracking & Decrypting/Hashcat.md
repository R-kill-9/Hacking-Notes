It's a password cracking tool used for recovering passwords from various hash types. Hashcat supports a wide range of hash algorithms, including common ones like MD5, SHA1, SHA256, as well as more advanced ones like bcrypt, scrypt, and Argon2. It can handle both single hashes and hash lists, making it useful for cracking passwords stored in databases, files, or captured network traffic.

| Option        | Description                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| **`-a 0`**    | Dictionary attack. Hashcat will try different words or word combinations from a predefined dictionary.  |
| **`-a 1`**    | Brute-force attack. Hashcat will try all possible combinations of characters until a match is found.    |
| **`-a 3`**    | Mask attack. Hashcat allows specifying a custom pattern or mask to generate possible word combinations. |
| **`-a 6`**    | Custom rules. A custom attack mode allowing the use of custom rules.                                    |
| **`-a 7`**    | Hybrid attack. Combines multiple attack methods for a more efficient cracking process.                  |
| **`-m 0`**    | Hash type MD5.                                                                                          |
| **`-m 100`**  | Hash type SHA1.                                                                                         |
| **`-m 500`**  | Hash type HMAC-SHA256.                                                                                  |
| **`-m 1800`** | Hash type sha512crypt.                                                                                  |
| **`-m 1000`** | NTLM hashes.                                                                                            |


```bash
# wordlist example: /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 0 <hash_file> <wordlist>
```
