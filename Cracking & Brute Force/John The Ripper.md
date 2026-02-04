**John the Ripper (JtR)** is a free and open-source password cracking tool. It is one of the most widely used password auditing tools because it combines multiple cracking techniques, automatically detects hash formats, and supports a large number of encryption and hashing algorithms.

## Wordlist Mode
**Wordlist mode** performs a dictionary attack by trying each word from one or more wordlists against the target hash.

```bash
# wordlist example: /usr/share/wordlists/rockyou.txt
john --wordlist=<wordlist> <hash_file>
```
Once we have already used the previous command, we can see the password and username found using:
```bash
john --show <hash_file>
```

#### How to Specify the Hash Format

You can use the `--format=<format>` flag followed by the hash type when running John the Ripper.


```bash
# wordlist example: /usr/share/wordlists/rockyou.txt
john --format=<format> --wordlist=<wordlist> <hash_file>
```

**Hash Formats Supported by John the Ripper**

| Hash format | Description |
|------------|-------------|
| afs | AFS (Andrew File System) password hashes |
| bfegg | bfegg hashes used in Eggdrop IRC bots |
| bf | Blowfish-based crypt(3) hashes |
| bsdi | BSDi crypt(3) hashes |
| crypt | Traditional Unix crypt(3) hashes |
| des | Traditional DES-based crypt(3) hashes |
| dmd5 | DMD5 (Dragonfly BSD MD5) password hashes |
| dominosec | IBM Lotus Domino 6/7 password hashes |
| episerver | EPiServer SID (Security Identifier) password hashes |
| hdaa | hdaa password hashes used in Openwall GNU/Linux |
| hmac-md5 | HMAC-MD5 password hashes |
| hmailserver | hMailServer password hashes |
| ipb2 | Invision Power Board 2 password hashes |
| krb4 | Kerberos 4 password hashes |
| krb5 | Kerberos 5 password hashes |
| LM | LM (Lan Manager) password hashes |
| lotus5 | Lotus Notes/Domino 5 password hashes |
| mscash | MS Cache password hashes |
| mscash2 | MS Cache v2 password hashes |
| mschapv2 | MS-CHAP v2 password hashes |
| mskrb5 | MS Kerberos 5 password hashes |
| mssql05 | MS SQL Server 2005 password hashes |
| mssql | MS SQL Server password hashes |
| mysql-fast | MySQL fast password hashes |
| mysql | MySQL password hashes |
| mysql-sha1 | MySQL SHA1 password hashes |
| netlm | NETLM (NT LAN Manager) password hashes |
| netlmv2 | NETLMv2 password hashes |
| netntlm | NETNTLM password hashes |
| netntlmv2 | NETNTLMv2 password hashes |
| nethalflm | NEThalfLM password hashes |
| md5ns | MD5 namespace password hashes |
| nsldap | OpenLDAP SHA password hashes |
| ssha | Salted SHA password hashes |
| NT | NT (Windows NT) password hashes |
| openssha | OpenSSH private key password hashes |
| oracle11 | Oracle 11 password hashes |
| oracle | Oracle password hashes |
| pdf | PDF document password hashes |
| phpass-md5 | PHPass-MD5 password hashes |
| phps | PHPS password hashes |
| pix-md5 | Cisco PIX MD5 password hashes |
| po | Sybase SQL Anywhere password hashes |
| rar | RAR (WinRAR) password hashes |
| raw-md4 | Raw MD4 password hashes |
| raw-md5 | Raw MD5 password hashes |
| raw-md5-unicode | Raw MD5 Unicode password hashes |
| raw-sha1 | Raw SHA1 password hashes |
| raw-sha224 | Raw SHA224 password hashes |
| raw-sha256 | Raw SHA256 password hashes |
| raw-sha384 | Raw SHA384 password hashes |
| raw-sha512 | Raw SHA512 password hashes |
| salted-sha | Salted SHA password hashes |
| sapb | SAP CODVN B (BCODE) password hashes |
| sapg | SAP CODVN G (PASSCODE) password hashes |
| sha1-gen | Generic SHA1 password hashes |
| skey | S/Key one-time password hashes |
| ssh | SSH password hashes |
| sybasease | Sybase ASE password hashes |
| xsha | Extended SHA password hashes |
| zip | ZIP (WinZip) password hashes |

---

## Single Crack Mode

**Single crack mode** is a rule-based attack that generates password candidates from information related to the user account. It is especially effective against **Linux password hashes** extracted from files such as `/etc/passwd` and `/etc/shadow`.

Example entry from `/etc/passwd`:

`r0lf:$6$ues25dIanlctrWxg$...:0:0:RolfSebastian:/home/r0lf:/bin/bash`

From this entry, John can infer:

- Username: `r0lf`
- Real name: `Rolf Sebastian`
- Home directory: `/home/r0lf`

#### Running Single Crack Mode

```bash
john --single <hash_file>
```

This mode is **fast** and works well when user-related metadata is available.


---

## Cracking Encrypted Files with \*2john Tools

John includes multiple **conversion tools** that extract hashes from encrypted files into a crackable format.

1. **Convert the  file to a hash format**:

```bash
<tool> <file> > <hash_file>
```

2. **Crack the hash file**:

```bash
john --wordlist=<wordlist> <hash_file>
```

3. **View the result**:

```bash
john --show <hash_file_generated>
```

**Some Tools supported by John the Ripper**

|**Tool**|**Description**|
|---|---|
|`pdf2john`|Converts PDF documents for John|
|`ssh2john`|Converts SSH private keys for John|
|`mscash2john`|Converts MS Cash hashes for John|
|`keychain2john`|Converts OS X keychain files for John|
|`rar2john`|Converts RAR archives for John|
|`pfx2john`|Converts PKCS#12 files for John|
|`truecrypt_volume2john`|Converts TrueCrypt volumes for John|
|`keepass2john`|Converts KeePass databases for John|
|`vncpcap2john`|Converts VNC PCAP files for John|
|`putty2john`|Converts PuTTY private keys for John|
|`zip2john`|Converts ZIP archives for John|
|`hccap2john`|Converts WPA/WPA2 handshake captures for John|
|`office2john`|Converts MS Office documents for John|
|`wpa2john`|Converts WPA/WPA2 handshakes for John|
If you want to know all the available tools execute `locate '*2john*'` on Kali.