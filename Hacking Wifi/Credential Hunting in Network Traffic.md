Even though modern applications commonly use **TLS encryption**, credential exposure in network traffic is still possible in several scenarios:

- Legacy systems
    
- Misconfigured services
    
- Test or development environments without HTTPS
    
- Older protocol versions without encryption
    

These situations allow attackers to **capture network traffic and extract sensitive information** such as usernames, passwords, and authentication hashes.

---

## Unencrypted vs Encrypted Protocols

|Unencrypted Protocol|Encrypted Counterpart|Description|
|---|---|---|
|HTTP|HTTPS|Transfers web pages and resources|
|FTP|FTPS / SFTP|File transfer|
|SNMP|SNMPv3|Network device monitoring|
|POP3|POP3S|Email retrieval|
|IMAP|IMAPS|Email management|
|SMTP|SMTPS|Email sending|
|LDAP|LDAPS|Directory services|
|RDP|RDP with TLS|Remote desktop access|
|DNS|DNS over HTTPS|Domain resolution|
|SMB|SMB 3.0 with TLS|File sharing|
|VNC|VNC with TLS|Remote graphical access|

If traffic is not encrypted, credentials can often be recovered directly from packet captures.

---

## Wireshark 

Wireshark is a packet analysis tool capable of inspecting both **live traffic** and **offline packet captures** (`.pcap`, `.pcapng`). It provides a powerful filtering engine to isolate relevant traffic.

### Common Use Cases

- Identify plaintext protocols
    
- Extract credentials from HTTP forms
    
- Analyze FTP, SMTP, POP3, SNMP authentication
    
- Track complete client-server conversations
    

---

## Useful Wireshark Filters

|Filter|Purpose|
|---|---|
|`ip.addr == 56.48.210.13`|Filter traffic for a specific IP|
|`tcp.port == 80`|Filter HTTP traffic|
|`http`|Show HTTP packets|
|`dns`|Show DNS traffic|
|`icmp`|Show ICMP packets|
|`tcp.flags.syn == 1 && tcp.flags.ack == 0`|Identify TCP connection attempts|
|`http.request.method == "POST"`|Locate POST requests|
|`tcp.stream eq 53`|Follow a specific TCP stream|
|`eth.addr == 00:11:22:33:44:55`|Filter by MAC address|
|`ip.src == X && ip.dst == Y`|Traffic between two hosts|

### Searching for Credentials in Wireshark

Wireshark allows searching for **specific strings within packet payloads**.

### Methods

- Display filter:
    

```text
http contains "passw"
```

- GUI search:
    

```
Edit → Find Packet
```

### Common Search Strings

- `password`
    
- `passwd`
    
- `username`
    
- `login`
    
- `user=`
    
- `pwd=`
    

HTTP POST requests over unencrypted connections frequently contain credentials in cleartext.

---

## Pcredz

Pcredz is an automated credential extraction tool designed to process **live traffic or packet capture files**.

### Supported Data Types

- Credit card numbers
    
- FTP credentials
    
- POP3 / IMAP / SMTP credentials
    
- SNMP community strings
    
- HTTP Basic, NTLM, and form-based credentials
    
- NTLMv1 / NTLMv2 hashes
    
- Kerberos (AS-REQ etype 23) hashes
    
- Credentials from SMB, LDAP, MSSQL, and DCE-RPC traffic
    


### Running Pcredz on a Capture File

```bash
./Pcredz -f demo.pcapng -t -v
```

#### Options

- `-f` : input capture file
    
- `-t` : show timestamps
    
- `-v` : verbose output
    
