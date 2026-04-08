A **WAF** (Web Application Firewall) is a security system designed to monitor, filter, and block HTTP/HTTPS traffic to and from a web application. Its main purpose is to protect web applications from various attacks, such as SQL injection, cross-site scripting (XSS), and other OWASP Top 10 vulnerabilities.

---

## WAFHunter

` WAFHunter` is a tool used for detecting and analyzing Web Application Firewalls (WAFs) that protect a target web application. WAFs monitor, filter, and block HTTP/HTTPS traffic to prevent attacks such as SQL injection, Cross-Site Scripting (XSS), and other OWASP Top 10 vulnerabilities. Identifying the presence and type of a WAF is crucial during penetration testing, as it helps tailor attack methods and avoid detection.

### Installation

WAFHunter can be installed directly from its GitHub repository:

```bash
git clone https://github.com/laramies/wafhunter.git
cd wafhunter
pip3 install -r requirements.txt
```

### Basic Usage

The simplest usage checks whether a WAF is present on a target domain:

```bash
python3 wafhunter.py -u http://example.com
```

Example output:

```text
[+] Target: http://example.com
[+] WAF Detected: Cloudflare
[+] WAF Type: CDN / Application Firewall
```

This indicates that Cloudflare is actively filtering traffic, which may block automated attacks or scans.

### Advanced Techniques

WAFHunter supports additional options to fine-tune detection:

- **Custom headers** to test WAF behavior with unusual requests.
    
- **Aggressive mode** to probe for evasive WAF rules.
    
- **Reporting** to log results for multiple domains at once.
    

Example scanning multiple targets:

```bash
python3 wafhunter.py -l targets.txt -o waf_results.txt
```


---
## Wafw00f
`WAFW00F` is an open-source tool used for detecting and identifying Web Application Firewalls (WAFs) that are protecting a web application.

```bash
wafw00f example.com
```

As we can see in the example, it shows that a WAF is protecting the application, in this case, Cloudflare.

![](Images/Wafw00f.png)