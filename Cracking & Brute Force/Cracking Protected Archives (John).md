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

---

## Cracking OpenSSL Encrypted GZIP Files

Not all password-protected files are immediately obvious. Some files may appear to be regular archives based on their extension, even though they are actually encrypted using **OpenSSL**. This is common with files encrypted using `openssl enc` and later compressed with GZIP.

#### Identifying OpenSSL-Encrypted Files

To determine the true format of a file, the `file` command can be used:

```bash
file GZIP.gzip
```

Example output:

```text
GZIP.gzip: openssl enc'd data with salted password
```

This indicates that the file is encrypted using OpenSSL and protected with a password.

#### Brute-Forcing OpenSSL GZIP Files

Cracking OpenSSL-encrypted files directly with password crackers may lead to **false positives** or complete failure. A more reliable method is to attempt decryption directly using `openssl` in a loop, extracting the contents only when the correct password is supplied.

**Brute-force One-Liner**

```bash
for i in $(cat rockyou.txt); do \
  openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz; \
done
```

- Attempts decryption using each password from `rockyou.txt`
    
- Suppresses error output
    
- Extracts files only when the correct password is used
    

During execution, multiple errors may appear and can be safely ignored:

```text
gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now
```


#### Verifying Successful Decryption

Once the correct password is found, files will be extracted successfully. Verify by listing the directory contents:

```bash
ls
```

Example output:

```text
customers.csv  GZIP.gzip  rockyou.txt
```

---

## Cracking BitLocker-Encrypted Drives

**BitLocker** is a full-disk encryption technology developed by Microsoft, available since Windows Vista. It uses AES encryption with 128-bit or 256-bit keys. Access can be recovered using either a **password/PIN** or a **48-digit recovery key**.

In enterprise environments, BitLocker is commonly used to protect virtual disks (`.vhd`, `.vhdx`) containing sensitive information.

---

#### Extracting BitLocker Hashes

To extract crackable hashes from a BitLocker-encrypted virtual drive, use `bitlocker2john`:

```bash
bitlocker2john -i Backup.vhd > backup.hashes
```

This produces **four hashes**:

- Two for the BitLocker password
    
- Two for the recovery key
    

Since recovery keys are long and randomly generated, we focus on cracking the **password hash** (`$bitlocker$0$...`).

```bash
grep "bitlocker\$0" backup.hashes > backup.hash
cat backup.hash
```

#### Cracking BitLocker with Hashcat

The Hashcat mode for `$bitlocker$0$` hashes is **22100**.

```bash
hashcat -a 0 -m 22100 backup.hash /usr/share/wordlists/rockyou.txt
```

- Uses dictionary attack
    
- Cracking speed is slow due to strong AES encryption
    
- Hardware performance has a significant impact
    

Example cracked result:

```text
$bitlocker$0$...:1234qwer
```

---

## Mounting BitLocker-Encrypted Drives

### Mounting on Windows

1. Double-click the `.vhd` file
    
2. Ignore the initial error
    
3. Open the BitLocker volume
    
4. Enter the recovered password
    


### Mounting on Linux (or macOS)
`
```bash
###############################
# BitLocker VHD Mounting Guide
###############################

# === VARIABLES YOU MUST ADJUST ===
# Path to the BitLocker-encrypted VHD file
VHD_PATH="/home/kill-9/Hacking/HTB-Academy/Private.vhd"

# BitLocker password
BITLOCKER_PASS="francisco"

# Mount directories (can be changed if desired)
WORKDIR="$HOME/Hacking/HTB-Academy/media"
BITLOCKER_DIR="$WORKDIR/bitlocker"
MOUNT_DIR="$WORKDIR/bitlockermount"

#################################
# 1. CLEAN PREVIOUS STATE
#################################

sudo umount "$MOUNT_DIR" 2>/dev/null
sudo umount "$BITLOCKER_DIR" 2>/dev/null
sudo losetup -D

#################################
# 2. PREPARE DIRECTORIES
#################################

mkdir -p "$BITLOCKER_DIR"
mkdir -p "$MOUNT_DIR"

#################################
# 3. ATTACH THE VHD AS A LOOP DEVICE
#################################

sudo losetup -f -P "$VHD_PATH"

# Verify loop device (take note of the NEW loop device, usually loop0)
lsblk

#################################
# 4. UNLOCK BITLOCKER VOLUME
#################################
# IMPORTANT:
# - Use the BitLocker partition (usually /dev/loop0p1)
# - Password is provided with -u

sudo dislocker /dev/loop0p1 -u"$BITLOCKER_PASS" -- "$BITLOCKER_DIR"

# If successful, this file will be created:
# $BITLOCKER_DIR/dislocker-file

#################################
# 5. MOUNT THE DECRYPTED FILESYSTEM
#################################

sudo mount -o loop "$BITLOCKER_DIR/dislocker-file" "$MOUNT_DIR"

#################################
# 6. ACCESS FILES
#################################

cd "$MOUNT_DIR"
ls -la

#################################
# 7. CLEANUP (RESTORE SYSTEM STATE)
#################################

cd ~
sudo umount "$MOUNT_DIR"
sudo umount "$BITLOCKER_DIR"
sudo losetup -D

#################################
# END
#################################

```