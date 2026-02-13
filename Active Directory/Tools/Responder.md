**Responder** is a tool used to poison LLMNR, NBT-NS, and mDNS requests in order to capture NTLM authentication hashes from machines on the same local network.

It listens for broadcast name resolution requests and responds maliciously, pretending to be the requested host.

---

## Why it works?

When a Windows machine cannot resolve a hostname through the hosts file, DNS cache, or configured DNS server, it falls back to multicast name resolution methods like LLMNR or NetBIOS. If a user mistypes a shared folder path (for example, `\\accountingserver\Reports` instead of `\\accountserver\Reports`), the system broadcasts a query to the local network asking which device owns that name. An attacker on the same subnet can spoof the response, impersonate the requested server, and trick the victim into authenticating to the attacker’s machine, allowing capture of NTLM credentials.

---

## Basic Usage

Start Responder on the correct interface:

```bash
sudo responder -I eth0
```

Common options:

```bash
sudo responder -I eth0 -rdw
```

Flags explanation:

- `-I` → Network interface
    
- `-r` → Enable NetBIOS poisoning
    
- `-d` → Enable DHCP poisoning
    
- `-w` → Start WPAD rogue proxy server
    

---

## What Happens Internally

1. Victim mistypes a hostname.
    
2. Victim sends LLMNR/NBT-NS broadcast.
    
3. Responder replies claiming ownership.
    
4. Victim attempts SMB/HTTP authentication.
    
5. NTLM hash is captured.
    

---

## Captured Hash Location

Hashes are stored in:

```
/usr/share/responder/logs/
```

Or similar directory depending on installation.

Example captured hash:

```
USER::DOMAIN:1122334455667788:NTLM_HASH:...
```

---

## Cracking NTLM Hashes

Using Hashcat (NTLMv2 mode 5600):

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```
