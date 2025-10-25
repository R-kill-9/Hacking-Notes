**John the Ripper** is a free password cracking software tool. It is among the  most frequently used password testing and breaking programs as it combines a number of  password crackers into one package, autodetects password hash types, and includes a  
customizable cracker. It can be run against various encrypted password formats  including several crypt password hash types most commonly found on various Unix  versions (based on DES, MD5, or Blowfish), Kerberos AFS, and Windows NT/2000/XP/2003 LM  
hash.


## Cracking passwords

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

**Common Hash Formats Supported by John the Ripper**

|**Format Name**|**Description**|
|---|---|
|**raw-md5**|Standard MD5 hash format (e.g., `098f6bcd4621d373cade4e832627b4f6`).|
|**ntlm**|Windows NTLM hash format (e.g., `098f6bcd4621d373cade4e832627b4f6`).|
|**lm**|Windows LM hash format, often used in older Windows versions (e.g., `aad3b435b51404eeaad3b435b51404ee`).|
|**crypt**|Traditional Unix crypt format (e.g., `$1$random$7k9Y19m9ay2nn0Cnkso2e/`).|
|**bcrypt**|Bcrypt format, used in many modern applications for storing passwords (e.g., `$2y$12$...`).|
|**sha256crypt**|SHA-256 encrypted passwords used in Unix systems (e.g., `$5$rounds=5000$...`).|
|**descrypt**|DES-based encryption for Unix passwords (e.g., `abC23jiN`).|
|**mssql2000**|Hash format for Microsoft SQL Server 2000 (e.g., `0x0100...`).|
|**mysql**|MySQL password hash format (e.g., `*A75C1E...`).|
|**krb5asrep**|Kerberos AS-REP hash format, used for ticket-based authentication (e.g., `user$krb5asrep$...`).|


## Cracking a zip file
1. **Convert the ZIP file to a hash format**:

First, you need to use the `zip2john` tool to convert the ZIP file into a hash that John the Ripper can work with.

```bash
zip2john <zip_file> > <hash_file_generated>
```

2. **Crack the hash file**:

Once you have the hash file, you can use **John the Ripper** with a wordlist or password list to try to discover the password.

```bash
john --wordlist=<wordlist> hash_file_generated
```

3. **View the result**:

Once John has finished trying passwords, you can view the found password with this command:

```bash
john --show <hash_file_generated>
```


## Cracking a SSH Key
If you want to **crack the password of an SSH key** (e.g., if the private key is protected by a password), you can use `ssh2john` to convert the SSH key to a format John the Ripper can handle. Here are the steps:

1. **Convert the SSH key to a hash**:

Use `ssh2john` to convert a private SSH key into a hash format. The output file will contain the hash of the SSH key, which can be processed by John the Ripper.

```bash
ssh2john <private_key_file> > <hash_file_generated>
```

2. **Crack the hash file**:

Use John the Ripper with a password list to attempt to discover the password for the private key.

```bash
john --wordlist=<wordlist> <hash_file_generated>
```

3. **View the result**:

Once John has finished trying passwords, you can view the found password with this command:

```bash
john --show <hash_file_generated>
```

4.  **Decrypt the SSH Key with the Cracked Password**

Now that you have the password, you can decrypt the SSH key and use it to access the server. 

```bash
ssh-keygen -p -f <path_to_private_key> -P <old_password> -N <new_password>
```

For example, if the cracked password is `kill-9`, you can update or regenerate the SSH private key:

```bash
ssh-keygen -p -f id_rsa -P kill-9 -N ""

```

## Cracking .kdbx Files (KeePass)
If you want to **crack the password** of a `.kdbx` file (KeePass), John the Ripper can be used with the help of an additional tool like `keepass2john` to convert the KeePass file into a hash.

1. **Convert the .kdbx file to a hash**:

Use `keepass2john` to convert the `.kdbx` file into a format that John the Ripper can handle. This command will extract the hash from the KeePass file:

```bash
keepass2john <file.kdbx> > <hash_file_generated>
```

2. **Crack the hash file**:

Now, use **John the Ripper** with a wordlist to attempt to crack the password for the KeePass file.

```bash
john --wordlist=<wordlist> <hash_file_generated>
```

3. **View the result**:

Once John has finished trying passwords, you can view the found password with this command:

```bash
john --show <hash_file_generated>
```

## Cracking a .pwsafe3 File (Password Safe)

If you want to **crack the password** of a `.pwsafe3` file (Password Safe), you can use **John the Ripper** to attempt to crack the password. Here’s how you do it:

1. **Convert the .pwsafe3 file to a hash:**

First, you need to convert the `.pwsafe3` file into a format that John the Ripper can process. You can use the `pwsafe2john` tool, which extracts the hash from the Password Safe file.

```bash
pwsafe2john <file.pwsafe3> > <hash_file_generated>
```

This command will output the hash into a file (e.g., `hash_file_generated`), which John the Ripper can then use.

 2. **Crack the hash file**:

Next, use **John the Ripper** with a wordlist to try cracking the password. You can use any standard wordlist (e.g., `rockyou.txt`).

```bash
john --wordlist=<wordlist> <hash_file_generated>
```

