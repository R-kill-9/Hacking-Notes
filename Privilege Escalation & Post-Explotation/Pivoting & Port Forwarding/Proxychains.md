**ProxyChains** works by intercepting an application’s network traffic and redirecting it through one or more proxy servers before reaching its final destination. It achieves this by modifying system calls that handle networking, effectively forcing the application to send its traffic through the configured proxies. 

When a command is executed with ProxyChains, it reads the configuration file (typically located at `/etc/proxychains.conf`) to determine the proxy chain settings and dynamically reroutes traffic as specified.
## Configure ProxyChains

- Edit the configuration file:

```bash
sudo nano /etc/proxychains.conf
# Add your proxy (e.g., from the pivot machine):
socks5 127.0.0.1 9050  
```

## Set Up a Pivot Machine

You can use tools like SSH or Metasploit to compromise a machine and establish a tunnel for traffic forwarding.

#### Using Metasploit

1. Compromise a target and establish a Meterpreter session.
```bash
run autorute -s <target_subnet>/24
```


2. Create a SOCKS proxy using the Metasploit `socks_proxy` module:

```bash
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 9050
run
```

#### Using SSH
- `-D 9050` sets up a dynamic SOCKS proxy on port 9050.

```bash
ssh -D 9050 user@target-machine
```

## Run Applications Through ProxyChains

- Prepend `proxychains` to any command to route its traffic through the proxy:
```bash
proxychains nmap -sT -Pn -p 22 192.168.1.0/24
```
- Ensure the command uses **TCP-based options**.