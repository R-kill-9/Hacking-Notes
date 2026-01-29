**Nmap** (Network Mapper) is a powerful network scanning tool used for host discovery, port scanning, service enumeration, OS detection, and security auditing. It is widely used in penetration testing and network defense.

---

## Common Scan Options

|Option|Description|
|---|---|
|`-sS`|TCP SYN stealth scan. Sends SYN packets and analyzes responses without completing the TCP handshake. Faster and less noisy than full TCP scans.|
|`-sT`|TCP connect scan. Completes the TCP handshake. More detectable but useful when SYN scans are not permitted.|
|`-sU`|UDP port scan. Slower and less reliable but necessary for discovering UDP services.|
|`-sV`|Service version detection. Identifies the application and version running on open ports.|
|`-sC`|Runs default NSE scripts for basic enumeration and vulnerability checks.|
|`-sn`|Ping scan. Discovers live hosts without scanning ports.|
|`-p-`|Scans all 65535 TCP ports.|
|`-p <port>`|Scans only the specified port(s).|
|`-Pn`|Skips host discovery and treats the target as alive. Useful when ICMP is blocked.|
|`-n`|Disables DNS resolution. Improves speed and reduces noise.|
|`-O`|OS detection using TCP/IP fingerprinting.|
|`--osscan-guess`|Makes an educated guess if OS detection is inconclusive.|
|`--open`|Shows only open ports.|
|`-vvv`|Increases verbosity.|
|`-iL <file>`|Scans a list of targets from a file.|
|`-T0` to `-T5`|Timing templates. Higher values are faster but noisier.|
|`--min-rate <number>`|Sets minimum packets per second to speed up scans.|
|`-oN/-oG/-oX`|Output formats: normal, grepable, and XML.|


```
nmap -sS -sCV -p21 <ip_address>
```

Performs a SYN scan with service/version detection and default scripts on port 21.

---

## Advanced Evasion Scan Example

```
nmap -sS -Pn -n -p- 10.129.2.80 --disable-arp-ping -source-port 53 -D RND:2
```

- `-sS`: Stealth SYN scan
    
- `-Pn`: Skips host discovery
    
- `-n`: No DNS resolution
    
- `-p-`: Scan all ports
    
- `--disable-arp-ping`: Avoids ARP discovery (useful in restricted networks)
    
- `--source-port 53`: Spoofs source port as DNS to bypass firewalls
    
- `-D RND:2`: Uses 2 random decoy IPs to obfuscate the real scanning host
    

This scan is designed to **evade firewalls, IDS, and IPS systems**.


#### IDS and IPS Considerations

**IDS (Intrusion Detection System)**

- Monitors network traffic and generates alerts.
    
- Does not block traffic.
    
- Nmap scans with high speed (`-T4`, `-T5`) or full port scans are often detected.
    
- SYN scans, decoys, and slow timing (`-T1`, `-T2`) can reduce detection.
    

**IPS (Intrusion Prevention System)**

- Actively blocks suspicious traffic.
    
- May drop packets or blacklist the scanning IP.
    
- Using `-Pn`, decoys (`-D`), spoofed source ports, and low packet rates helps bypass IPS.
    

---

## Nmap Scripting Engine (NSE)

NSE extends Nmap by allowing scripted interaction with services.

Scripts are located in:

```
/usr/share/nmap/scripts/
```

#### Script Capabilities

- Vulnerability detection
    
- Service enumeration
    
- Authentication brute-force
    
- Configuration auditing
    
- Exploitation checks
    

#### Useful NSE Categories

- `auth`
    
- `brute`
    
- `default`
    
- `discovery`
    
- `exploit`
    
- `safe`
    
- `vuln`

#### Running NSE Scripts

```
nmap --script <script-name> <target>
```

#### Script Arguments

```
nmap --script <script-name> --script-args <key>=<value> <target>
```

Example:

```
nmap --script http-brute --script-args userdb=users.txt,passdb=pass.txt 10.10.10.10
```
