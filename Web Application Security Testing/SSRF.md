**SSRF** (Server-Side Request Forgery) is a type of vulnerability where an attacker can manipulate a server to make requests to unintended internal or external systems. This vulnerability occurs when a web application allows users to provide a URL or network address that the server then uses to make a request. If not properly validated, an attacker can exploit this functionality to make the server access resources that are normally not accessible from the outside.

## Example of How SSRF Works

Suppose there is a web application that allows users to provide a URL of an image for the server to download and display within the application. If this input is not properly validated, an attacker could provide a URL pointing to an internal resource within the server's network, such as `http://localhost/admin`, or to an internal service on a specific port, like `http://localhost:8080/secret-data`.
# SSRFmap
**ssrfmap.py** is a tool designed to automate the exploitation of SSRF vulnerabilities. It allows attackers or pentesters to utilize and manipulate input parameters that trigger server-side requests to perform various malicious activities, such as port scanning, service enumeration, and exploitation of other internal resources.
### Installation 
```bash
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt
```
### Configuration
The `request.txt` file should contain the full HTTP request that the web application makes when provided with a URL. This file might look like this:
```bash
GET /fetch?url=http://example.com/image.jpg HTTP/1.1
Host: vulnerable-app.com
User-Agent: Mozilla/5.0
```
## Port scanning
To scan ports on an internal IP address, you can use the following command:
- Parameters: 
	- `-r`: name of the file where the request has been saved.
	- `-p`: name of the potentially vulnerable parameter on the request.
	- `-m`: module that we want to execute, in this case portscan.
```bash
python3 ssrfmap.py -r <request> -p <vulnerable_parameter> -m portscan
```
## Service enumeration
To enumerate services, you can use:
```bash
`python3 ssrfmap.py -r request.txt --url "http://127.0.0.1:8000" --data`
```