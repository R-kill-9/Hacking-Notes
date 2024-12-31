Pivoting  is the process of using a compromised system as a gateway to access other machines or networks that are not directly reachable.

1. **Compromise a Host**
- Gain access to a machine using exploits in Metasploit, resulting in a Meterpreter session or other payload connection. 
- Identify a network that was not accessible before.

2.  **Set Up Routes**

- Use the `autoroute` module to add a route through the compromised host. This will enable Metasploit to send traffic through the host to the target network.

```bash
run autoroute -s [target_subnet]
```

3. **Verify the Routes**

- Check the routes added to ensure connectivity:

```bash
msf6 > route
```

4. **Run Scans Through the Pivot**

- Perform reconnaissance using modules like `auxiliary/scanner/portscan/tcp` or `auxiliary/scanner/http/http_version` through the pivoted route.

```bash
use auxiliary/scanner/portscan/tcp
set RHOSTS <discovered_ip>
run
```

5. **Forward Traffic**

Once the pivot is set up, you can also use Metasploit to create a SOCKS proxy, allowing you to route all traffic through the compromised machine.

```bash
# Ensure that the srvport is defined at /etc/proxychains4.conf and the socks version in use. 
use auxiliary/server/socks_proxy
set SRVPORT 9050
# If our attacker machine is configured with proxychains4 we will need to specify the version 4a
set VERSION <version>
run
```

6. **Running Applications Through ProxyChains** 

Once you have set up a SOCKS proxy either through Metasploit or SSH, you can use **ProxyChains** to route the traffic of various tools through the proxy.

```bash
proxychains nmap -sT -Pn -p 22 192.168.1.0/24
```