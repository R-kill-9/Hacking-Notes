Technical notes for **unauthenticated** reconnaissance of Windows Active Directory environments, extracted from [orange-cyberdefense](https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg).


---

## Network Scanning

Initial step to map the environment, detect live hosts, and identify exposed services before deeper enumeration.

### SMB Sweep

Scan an IP range for SMB-enabled hosts and gather OS, domain name, and share information without authentication:

```bash
nxc smb <ip_range>
```

### Host Discovery & Service Enumeration
Identify running services and potential entry points:

```bash
# Full TCP scan of all ports with default scripts and version detection
nmap -Pn -sC -sV -p- -oA <output> <ip>

# UDP services detection
nmap -sU -sC -sV -oA <output> <ip>

# Check for known SMB vulnerabilities
nmap -Pn --script 'smb-vuln*' -p139,445 <ip>

# Quick scan of the most common ports
nmap -Pn -sV --top-ports 50 --open <ip>

# Detect live hosts with a ping sweep
nmap -sP <ip_range>
```

These scans reveal which protocols (SMB, LDAP, Kerberos) are exposed for further testing.

### Find Domain Controllers

Locate servers providing key AD services:
```bash
# Identify Kerberos servers (port 88)
nmap -p 88 --open <ip_range>

# Retrieve DC SRV records from DNS
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>

# Display local interface information and gateway details
nmcli dev show <interface>
```

Knowing the DC IP is critical for LDAP, Kerberos, and SMB enumeration.

### DNS Zone Transfer

Attempt to pull the full DNS database if misconfigured:
```bash
dig axfr <domain_name> @<name_server>
```

A successful transfer reveals hostnames, IPs, and internal structure.



---

## SMB Shares (Anonymous & Guest Access)

Check for unauthenticated access to shared resources:
```bash
# Enumerate with guest user
netexec smb <ip> -u 'guest' -p '' --shares

# List SMB shares anonymously
smbclient -U '%' -L //<ip>

# Automated enumeration with multiple checks
enum4linux-ng.py -a -u '' -p '' <ip>

# Sweep for shares with null or guest sessions
nxc smb <ip_range> -u 'a' -p ''
nxc smb <ip_range> -u '' -p ''
```

Misconfigured shares may expose sensitive files, configuration data, or additional user accounts.

---

## LDAP Enumeration

Query LDAP services without credentials to collect domain information:
```bash
# Retrieve naming contexts and domain info
ldapsearch -x -H ldap://<dc_ip> -s base

# Detect LDAP services and gather attributes
nmap -n -sV --script 'ldap* and not brute' -p 389 <dc_ip>
```

Anonymous LDAP binds can reveal domain names, user lists, and organizational units.

---

## User Enumeration

Identify valid usernames to enable password spraying, Kerberoasting, or brute-force attacks.
```bash
# Enumerate domain users via RID brute force
nxc smb <dc_ip> --rid-brute 10000

# To extract the discovered usernames more cleanly, run:
netexec smb <dc_ip> -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' | sed -n "s/.*\\\\\([^ ]*\).*/\1/p" | sort -u

# List users through SMB directly
nxc smb <dc_ip> --users

# List members of the Domain Users group
net rpc group members 'Domain Users' -W '<domain>' -I <ip> -U '%'
```

Valid usernames are essential for Kerberos attacks or password guessing.

### Kerberos-Based Enumeration

Kerberos can leak information even without credentials:
```bash
# Enumerate valid usernames with Nmap script
nmap -p 88 --script=krb5-enum-users \
--script-args="krb5-enum-users.realm=<domain>,userdb=<user_list_file>" <dc_ip>

# High-speed user enumeration
kerbrute userenum -d <domain> --dc <dc-ip> <userlist>
```

These techniques detect accounts by observing differences in Kerberos responses.

---

## Poisoning

Intercept or relay authentication requests to capture NTLM or Kerberos hashes.
```bash
# LLMNR / NBT-NS / mDNS poisoning
responder -I <interface>

# Force IPv6 to exploit DHCPv6 and relay attacks
mitm6 -d <domain>

# Inject into HTTP, SMB, or LDAP traffic
bettercap

# ARP poisoning for man-in-the-middle
bettercap
```

Capturing hashes from these protocols can allow offline cracking or relay attacks.

