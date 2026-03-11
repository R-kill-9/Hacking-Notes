**SOAPHound** is a tool used to collect Active Directory data through Microsoft Exchange Web Services (EWS) using SOAP requests.  
The collected data can then be converted to BloodHound-compatible JSON files to analyze Active Directory attack paths.

SOAPHound is especially useful when:

- LDAP enumeration is restricted
- BloodHound collectors are detected
- Direct AD queries are monitored

Instead of querying LDAP, SOAPHound leverages **Exchange Web Services (EWS)** to obtain relationships between users, groups, and mailboxes.

Repository:

```text
https://github.com/FalconForceTeam/SOAPHound
```

---

## Requirements

Typical requirements to run SOAPHound:

- Valid domain credentials
- Access to Exchange Web Services (EWS)
- Network connectivity to the Exchange server

Typical EWS endpoint:

```text
https://exchange.domain.local/EWS/Exchange.asmx
```

Test access to the endpoint:

```bash
curl -k https://exchange.domain.local/EWS/Exchange.asmx
```

If accessible, the server will respond with an **Exchange Web Services SOAP endpoint page**.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/FalconForceTeam/SOAPHound.git
cd SOAPHound
```

Install dependencies:

```bash
pip3 install -r requirements.txt
```

---

## Usage

Execute the tool with a valid domain user:

```bash
python3 soaphound.py \
-u user \
-p Pass123 \
-d domain.local \
-e exchange.domain.local
```

### Output Files

SOAPHound generates **BloodHound-compatible JSON files**.

Typical output:

```text
users.json
groups.json
permissions.json
delegations.json
```

These files contain relationships such as:

```text
User → FullAccess → Mailbox
User → SendAs → Mailbox
User → FolderPermission → Mailbox
```
