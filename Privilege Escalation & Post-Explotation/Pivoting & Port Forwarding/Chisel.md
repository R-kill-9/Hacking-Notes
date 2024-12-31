**Chisel** is a TCP/UDP tunnel over HTTP that enables secure port forwarding, often used in penetration testing to bypass firewalls and NAT.

- You can download the Chisel last releases here: [link](https://github.com/jpillora/chisel/releases)
- Good explanation of how to use it: [explanation](https://deephacking.tech/pivoting-con-chisel/)

## Local Port Forwarding

Allows forwarding traffic from a local port to a specific port on the target machine through the Chisel server.

**Target machine**
```bash
./chisel server -p <port>
```
**Local machine**
```bash
chisel client <chisel server address>:<chisel server port> <local port to open>:<address to point to>:<port to point to on the target address>
```

## Remote Port Forwarding 

Allows opening a port on the **target machine** (via the Chisel client) that points to a service on the **local machine**.

**Local machine**
```bash
chisel server -p 9999 --reverse
```
**Target machine**
```bash
./chisel client <local_machine_ip>:<local_listener_port> R:<remote_port_to_open>:127.0.0.1:<target_machine_port_to_open>
```

## Dynamic Port Forwarding
Creates a local SOCKS proxy that dynamically forwards traffic to any destination through the Chisel server.

```bash
./chisel client <server_ip>:<port> dynamic :<local_port>
```


## SOCKS Proxy in Reverse Mode

The following command creates a **proxy SOCKS on the Chisel server**, routing traffic through the client (victim machine). This sets up a SOCKS proxy on the **Chisel server**, which routes traffic from the server through the client. It is particularly useful when the server (attacker) needs access to the client’s internal network or services.

- **Server (Attacker Machine):** Ensure the server is running in reverse mode:
```
./chisel server -p 9999 --reverse
```
- **Client (Victim Machine):** Execute the following command on the client.    
```
./chisel client <server_ip>:<server_port> R:socks
```
- **Use ProxyChains with a tool**. Now you can use `proxychains` to route the traffic of any command through that proxy SOCKS.
```
proxychains nmap -sT -p 80,443 <target_ip>
```
