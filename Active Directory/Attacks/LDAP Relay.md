The **LDAP Relay Attack** is an attack that abuses the **NTLM authentication** protocol by transparently intercepting a client's NTLM hash and **relaying** it to a target Domain Controller's **LDAP or LDAPS** service.

The primary goal of this attack is not just to access a file share, but to gain **full domain administrative control** by modifying objects within Active Directory.

---

## Key Concepts

|Concept|Description|
|---|---|
|**LDAP/LDAPS**|The **Lightweight Directory Access Protocol** (TCP port **389**) and its secure version, **LDAPS** (TCP port **636**), used by Domain Controllers for directory service lookups and modifications.|
|**NTLM Authentication**|The vulnerable challenge/response protocol whose hash is captured and relayed. The attack works because the attacker does not need the plaintext password, only the ability to forward the hash during the challenge-response exchange.|
|**Relay Attack**|A Man-in-the-Middle (MITM) technique where the attacker's machine acts as a conduit: receiving the NTLM authentication attempt from a victim and immediately forwarding it to the target Domain Controller.|
|**Coercion/Spoofing**|The initial step to trick a victim client (often a Domain Controller or high-privilege account) into authenticating to the attacker's machine. Tools like **Responder** (IPv4) or **mitm6** (IPv6) are used for this.|

---

## Basic Attack Process (IPv4)

1. **Authentication Coercion/Capture:** The attacker uses a tool like **Responder** to listen for unauthenticated name resolution requests (LLMNR/NBT-NS) or actively coerces an authentication (e.g., via PetitPotam, which forces a DC to authenticate to an attacker-controlled server).

```bash
sudo responder -I eth0
``` 

2. **Setting Up the LDAPS Relay with Impacket:** The attacker uses Impacket's `ntlmrelayx.py` script. The target is explicitly set to the **LDAPS** service of the Domain Controller.
```bash
sudo impacket-ntlmrelayx -t ldaps://<domain_name> -smb2support -socks
``` 
- `-t ldaps://<domain_name>`: Specifies the **secure LDAP** service as the target.

- `-smb2support`: Ensures compatibility with modern NTLM challenge-response sequences.

- `-socks`: Activates a local **SOCKS proxy** (usually on port 1080) that allows the attacker to use other tools (like `proxychains`) to interact with the domain as the relayed user.

3. **Post-Authentication Actions (Direct Access):** If the relayed user has high privileges, `ntlmrelayx` can perform direct domain compromise actions:

- `--add-computer`: Create a new computer object in AD for potential **Resource-Based Constrained Delegation (RBCD)** attack.

- `--delegate-access`: Perform an RBCD attack against a computer object (often the DC itself).

- `--dump-secrets`: Attempt to execute a **DCSync** attack to retrieve all password hashes from the entire domain (requires high privileges).


---

### Interactive Shell Access

For a more granular, interactive session with the relayed credentials, the `-i` flag is used. This is often leveraged to perform specific LDAP queries or manual manipulation.

1. **Start the relay using Interactive Mode (`-i`):**
```bash
impacket-ntlmrelayx -wh <ip> -t ldaps://<domain_name> -smb2support -i
``` 
- `-i`: Starts an **interactive LDAP shell** listener (e.g., on port 9999) after a successful relay.

2. **Connect to the Interactive Shell:** The attacker connects locally to the port opened by `ntlmrelayx` to begin issuing commands as the relayed user.
```bash
rlwrap nc localhost 9999
``` 

### IPv6 LDAPS Relaying Attack Process

This method exploits the fact that Windows clients prioritize IPv6, even when not actively used, to redirect all DNS resolution to the attacker.

1. **IPv6 DNS Spoofing:** The attacker runs **mitm6** to impersonate a DHCPv6/DNSv6 server, causing domain-joined Windows hosts to update their DNS configuration and use the attacker's machine for name resolution.
```bash
sudo mitm6 -i eth0 -d <domain_name> --debug
``` 

2. **Relay NTLM over IPv6 to LDAPS:** When a client attempts to access a resource, the attacker's DNS server redirects the request to the attacker's IPv6 address. The client sends its NTLM authentication, which is then relayed to LDAPS using the `-6` flag.
```bash
impacket-ntlmrelayx -6 -wh <ip> -t ldaps://<domain_name> -smb2support -l looted_ad/ -i
``` 
- `-6`: Enables IPv6 listening and relaying.

- `-l looted_ad/`: Directs the tool to save any credentials or looted information to the specified local directory.

- The goal remains the same: compromise the Domain Controller via a high-privilege relayed account.