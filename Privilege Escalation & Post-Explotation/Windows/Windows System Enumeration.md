## Gathering Basic System Information

- **`systeminfo`**  
Retrieves detailed system information, including the OS version, architecture, hotfixes, and more.
```bash
systeminfo
```
 
- **`hostname`**  
Displays the computer's hostname.
```bash
hostname
```

- **`ver`**  
Displays the current Windows version.
```bash
ver
```

- **`echo %username%`**  
Displays the current logged-in user.
```bash
echo %username%
```

## Users and Groups Enumeration
- **`query user`**
Displays the currently log on users.
```bash
query user
```
- **`net user`**  
Lists all user accounts on the system.
```bash
net user
```
- **`net user [username]`**  
Displays detailed information about a specific user.
```bash
net user [username]
```
- **`net localgroup`**  
Lists all local groups.
```bash
net localgroup
```
- **`net localgroup [groupname]`**  
Displays members of a specific group.
```bash
net localgroup [groupname]
```


## Network Configuration

- **`ipconfig /all`**      
Displays detailed network configuration, including IP address, DNS servers, and MAC address.

```bash
ipconfig /all
```

- **`route print`**  
Displays the system's routing table.
```bash
route print
```

- **`netstat -ano`**  
Lists active network connections, including process IDs.
```bash
netstat -ano
```

- **`arp -a`**  
Displays the ARP table.
```bash
arp -a
```

## Processes and Services

#### Processes
- **`tasklist`**  
Displays all running processes along with their Process ID (PID) and memory usage.

```bash
tasklist
```

- **`tasklist /svc`**  
Lists services associated with each process.
```bash
tasklist /svc
```

- **`wmic process list full`**  
Provides a detailed list of all running processes.
```bash
wmic process list full
```

- **`schtasks /query /fo LIST /v`**  
Enumerates all the scheduled tasks.
```bash
schtasks /query /fo LIST /v
```

#### Services

- **`net start`**  
Lists all running services.
```bash
net start
```

- **`wmic service get name,displayname,state,startmode`**  
Retrieves a concise summary of all services.
```bash
wmic service get name,displayname,state,startmode
```
- **`sc query`**
Displays the status of all services on the system.
```bash
sc query
```

- **`sc qc [service_name]`**  
Displays configuration details of a specific service.
```bash
sc qc wuauserv
```

## Network and Shared Resources Enumeration
- **`net view`** 
Lists available shared resources on a local network, such as computers or shared folders. It helps to discover devices and resources accessible in the network.  

```bash
net view
```

- **`net use`** 
This command is used to connect, disconnect, or manage connections to shared resources like network drives or printers. It allows mapping shared folders as network drives.  

```bash
net use Z: \\ComputerName\SharedFolder
```