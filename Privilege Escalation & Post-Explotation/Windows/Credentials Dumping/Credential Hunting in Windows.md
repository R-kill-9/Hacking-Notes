**Credential hunting** is the systematic process of searching a Windows system for stored authentication material such as passwords, hashes, keys, or tokens. Once access to a Windows host is obtained (via GUI like RDP or CLI such as PowerShell/CMD), credential hunting can significantly accelerate lateral movement and privilege escalation.

This technique relies on the fact that users and applications often store credentials insecurely across the filesystem, configuration files, memory, or application-specific storage.

---

## Built-in Search Tools

### Windows Search (GUI)

When GUI access is available, Windows Search can be used to locate files and settings containing specific keywords. By default, it searches:

- Indexed file locations
    
- OS configuration settings
    
- Application shortcuts
    

This method is quick but limited to indexed locations unless advanced options are configured.

---

## LaZagne

[LaZagne](https://github.com/AlessandroZ/LaZagne/releases/) is a post-exploitation tool designed to retrieve credentials stored by various applications on Windows. It consists of multiple modules, each targeting a specific category of software.

#### Key LaZagne Modules

- **browsers**  
    Extracts stored credentials from browsers such as Chrome, Firefox, Edge, and Opera.
    
- **chats**  
    Targets chat applications (e.g., Skype).
    
- **mails**  
    Extracts credentials from email clients like Outlook and Thunderbird.
    
- **memory**  
    Attempts to retrieve credentials from process memory, including KeePass and LSASS-related data.
    
- **sysadmin**  
    Extracts credentials from configuration files of administrative tools such as WinSCP and OpenVPN.
    
- **windows**  
    Targets Windows-specific credential stores, including Credential Manager and LSA secrets.
    
- **wifi**  
    Dumps stored Wi-Fi credentials.
    

#### Execution

Once transferred to the target system, LaZagne can be executed from the command line:

```cmd
start LaZagne.exe all
```

The `all` option runs every available module. Using the `-vv` flag increases verbosity and shows detailed execution steps.

LaZagne highlights how frequently credentials are stored insecurely in plaintext or reversibly encrypted formats.

---

## Pattern-Based Searching with findstr

The Windows `findstr` utility can be used to search for strings across multiple file types recursively. This is especially useful for identifying credentials embedded in configuration files or scripts.

Example command:

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.ps1 *.yml
```

Explanation:

- `/S` – search recursively
    
- `/I` – case-insensitive
    
- `/M` – print filenames only
    
- `/C:` – treat search string as a literal
    

This method is effective for locating hardcoded credentials in plaintext files.

---

## Additional Credential Storage Locations

When hunting credentials on Windows systems, the following locations should also be considered:

- Group Policy Preferences passwords in the SYSVOL share
    
- Scripts stored in SYSVOL or IT file shares
    
- `web.config` files on development machines or internal web servers
    
- `unattend.xml` files used during Windows installation
    
- Active Directory user or computer description fields
    
- KeePass databases (subject to master password recovery)
    
- User home directories and shared folders
    
- Documents with indicative names such as `pass.txt`, `passwords.xlsx`, or `credentials.docx`
    
