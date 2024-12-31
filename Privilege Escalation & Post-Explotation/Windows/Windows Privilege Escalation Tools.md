
# winPEAS.exe <a name="wpeas"></a>

winPEAS.exe is an executable that, once we have a reverse shell, will display files with possible critical information in red.

Example:

1. First, download it using PowerShell:
````bash
wget https://github.com/carlospolop/PEASS-ng/releases/tag/20231002-59c6f6e6
````
2.  Switch to PowerShell in your terminal: 
````bash
powershell
````
3. Finally, execute winPEAS.exe:
````bash
C:\Users\sql_svc\Downloads> .\winPEASx64.exe
````


# psexec.py <a name="pspy"></a>
**psexec.py** is a tool that allows you to remotely execute processes on other systems over a network.

````bash
python3 psexec.py administrator@{TARGET_IP}
````

# whoami
When you run `whoami /priv`, you will receive a list of the privileges assigned to your user account, along with their status (enabled or disabled). The output typically includes:

- **Privilege Name**: A brief description of each privilege.
- **State**: Indicates whether the privilege is enabled (Enabled) or disabled (Disabled).
#### Example of Usage
```bash
whoami /priv
```
The output might look something like this:
```bash
PRIVILEGES INFORMATION
-----------------------
Privilege Name                    State
===========================================
SeShutdownPrivilege                Enabled
SeBackupPrivilege                  Enabled
SeRestorePrivilege                 Disabled
SeChangeNotifyPrivilege            Enabled
SeTakeOwnershipPrivilege           Enabled
```

## net view and net use commands
`net view` lists available shared resources on a local network, such as computers or shared folders. It helps to discover devices and resources accessible in the network.  

```bash
net view
```

`net use` is used to connect, disconnect, or manage connections to shared resources like network drives or printers. It allows mapping shared folders as network drives.  

```bash
net use Z: \\ComputerName\SharedFolder
```