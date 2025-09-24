## Authentication Spraying

**Authentication Spraying** is an attack technique where an attacker attempts to log in to multiple accounts using a small set of credentials, avoiding account lockouts and reducing detection.

#### Key Concepts

- **Targets**: Services like SMB, WinRM, RDP, and cloud platforms (O365, Azure AD).
- **Detection Evasion**: Slow authentication attempts to avoid triggering account lockout policies.

- **Tools**: Impacket `netexec`, Impacket `spray.py`, Metasploit.


#### Method

1. **Enumerate Users**
    - Gather usernames using tools such as `enum4linux`, `ldapsearch`, or `kerbrute`.

2. **Attempt Authentication with Common Credentials**   

- Use `netexec` to test username/password combinations:

```bash
netexec smb <target_ip> -u <username> -p <password>
```

- To check administrative access:
```bash
netexec smb <target_ip> -u <username> -p <password> --admin
```

3. **Enable RDP Remotely**

- With administrative access, enable RDP using the `rdp` module in `netexec`:
```bash
netexec <target_ip> -u <username> -p <password> -M rdp action=enable
```



---

## Password Spraying

**Password Spraying** is a specific type of Authentication Spraying where the attacker tests a small set of common passwords across many accounts instead of multiple passwords on a single account.

#### Key Concepts

- **Brute Force vs Password Spraying**:
    - Brute Force: Many passwords on a single account → high chance of lockout.
        
    - Password Spraying: Few passwords across many accounts → reduces detection.
        
- **Common Passwords**: Examples include `Password1!`, `Summer2025`, `Welcome123`.

#### Method

1. **Enumerate Users**
    
    - Gather a list of usernames from Active Directory enumeration, leaked lists, or public sources.
        
2. **Attempt Authentication with Common Passwords**
    
- Using `netexec`:

```bash
netexec smb <target_ip> -u <username> -p <password>
```

- Using Impacket `spray.py` for automation:

```bash
python3 spray.py -u users.txt -p passwords.txt -d DOMAIN -o output.txt
```

3. Validate Successful Logins

    - Analyze results to identify accounts that accepted the password.