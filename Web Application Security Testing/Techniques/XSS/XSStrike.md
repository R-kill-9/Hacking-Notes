**XSStrike** is an automated tool used to **detect and exploit Cross-Site Scripting (XSS) vulnerabilities**. It analyzes web applications, identifies potential injection points, and generates context-aware payloads to test whether JavaScript execution is possible.

Unlike basic scanners that rely on predefined payload lists, XSStrike performs **intelligent analysis of the target’s response** and dynamically crafts payloads that bypass filters and match the HTML context in which the input is reflected.


---

## Installation

XSStrike is written in Python and can be installed directly from its repository.

Clone the repository:

```bash
git clone https://github.com/s0md3v/XSStrike.git
```

Navigate to the directory:

```bash
cd XSStrike
```

Install the required dependencies:

```bash
pip3 install -r requirements.txt
```

---

## Basic Usage

The most basic usage involves specifying a target URL that contains parameters.

Example command:

```bash
python3 xsstrike.py -u "http://target.com/page.php?q=test"
```

XSStrike will analyze the response and test whether the `q` parameter can be used to inject JavaScript.

---

## Testing Multiple Parameters

If a page contains several parameters, XSStrike can analyze them individually.

Example:

```bash
python3 xsstrike.py -u "http://target.com/page.php?id=1&search=test"
```

The tool will test each parameter to determine whether the input is reflected in the response and whether it can lead to XSS.

---

## Crawling a Website

XSStrike includes a crawler that can automatically discover additional pages and parameters.

Example command:

```bash
python3 xsstrike.py -u "http://target.com" --crawl
```

The crawler will:

- Explore internal links
    
- Identify parameters
    
- Test discovered endpoints for potential XSS vulnerabilities
    

---

## POST Request Testing

XSStrike can also test forms that use POST requests.

Example command:

```bash
python3 xsstrike.py -u "http://target.com/login" --data "username=test&password=test"
```

This allows the tool to analyze form submissions and determine whether user-controlled input can trigger XSS.
