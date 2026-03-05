If the target network has no DHCP, you must configure a static IP manually to connect via Ethernet.

---

## 1. Identify Your Network Interface

Connect the Ethernet cable and run:

```bash
ip a
```

Your interface may appear as `eth0`, `enp0s3`, `enp3s0`, etc.  
For this example, we will use `eth0`.

---

## 2. Assign a Temporary Static IP

Assume the network provides the following:

- IP: `192.168.10.50`
    
- Netmask: `255.255.255.0`
    
- Gateway: `192.168.10.1`
    
- DNS: `192.168.10.10` (usually the Domain Controller)
    

Run:

```bash
sudo ip addr add 192.168.10.50/24 dev eth0
sudo ip link set eth0 up
sudo ip route add default via 192.168.10.1
```

---

## 3. Configure DNS

Edit the resolver configuration:

```bash
sudo nano /etc/resolv.conf
```

Add:

```
nameserver 192.168.10.10
```

---

## 4. Verify Connectivity

Test connectivity to the gateway and domain controller:

```bash
ping 192.168.10.1
ping 192.168.10.10
```

If replies are received, the network configuration is correct.

---

## 5. Make Configuration Persistent (Optional)

Edit:

```bash
sudo nano /etc/network/interfaces
```

Add:

```ini
auto eth0
iface eth0 inet static
    address 192.168.10.50
    netmask 255.255.255.0
    gateway 192.168.10.1
    dns-nameservers 192.168.10.10
```

Restart networking:

```bash
sudo systemctl restart networking
```

---

## 6. Notes for AD Audits

- Confirm the IP range, gateway, and Domain Controller IP.
    
- Check for VLANs or network access controls (802.1X).
    
- Test that DNS resolution works with the AD domain:
    

```bash
nxc smb <IP_DC>
```

- Verify IP, routes, and DNS before starting enumeration:
    

```bash
ip a
ip route
cat /etc/resolv.conf
```

This ensures your Kali machine is ready for Active Directory reconnaissance and auditing.
