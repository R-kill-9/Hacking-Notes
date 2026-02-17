During internal network assessments, there may be **Windows environments** where SSH pivoting is not available. In these situations, pivoting must rely on native Windows technologies.

**SocksOverRDP** enables pivoting by leveraging **Dynamic Virtual Channels (DVC)** from the Windows Remote Desktop Services (RDS).

#### Dynamic Virtual Channels (DVC)

DVC allows data streams to be tunneled inside an RDP session. Legitimate uses include:

- Clipboard synchronization
    
- Audio redirection
    
- Device sharing
    

However, DVC can also transport **arbitrary network packets**, allowing the creation of a SOCKS proxy tunneled through an RDP connection.

---
### Required Files

Download on the attacker machine:

- [SocksOverRDP](https://github.com/nccgroup/SocksOverRDP/releases) x64 binaries
    
- [Proxifier Portable](https://www.proxifier.com/download/#win-tab) (ProxifierPE.zip)
    

Purpose:

- Centralized staging
    
- Easy transfer to compromised hosts
    

---

### 1. Initial RDP Connection and File Transfer

Connect to the foothold host using `xfreerdp` and transfer the archive.

Example:

```bash
xfreerdp /v:<TARGET_IP> /u:<USER> /p:<PASSWORD> /drive:share,/local/path
```

Copy `SocksOverRDP-x64.zip` to the target desktop.

---

### 2. Registering the SocksOverRDP Plugin

On the Windows foothold system, register the DLL:

```cmd
regsvr32.exe SocksOverRDP-Plugin.dll
```

Expected result:

- Successful registration message.
    
- Plugin becomes available to RDP sessions.
    

This step enables the SOCKS tunnel through the RDP virtual channel.

---

### 3. Establish RDP Session with Plugin Enabled

Connect to the victim target using the native RDP client:

```cmd
mstsc.exe
```
After login:

- SocksOverRDP plugin initializes automatically.
    
- SOCKS proxy listens on:
    

```
127.0.0.1:1080
```

---

### 4. Deploy and Start the SOCKS Server

Transfer either:

- `SocksOverRDP-x64.zip`  
    or
    
- `SocksOverRDP-Server.exe`
    

Run with Administrator privileges:

```cmd
SocksOverRDP-Server.exe
```

Expected output:

- Channel opened over RDP
    
- SOCKS tunnel established
    

---

### 5. Verify SOCKS Listener

Confirm the listener is active:

```cmd
netstat -antb | findstr 1080
```

Expected:

```
TCP    127.0.0.1:1080     0.0.0.0:0     LISTENING
```

This confirms the local SOCKS proxy is operational.

---

### 6. Configure Proxifier

Transfer **Proxifier Portable** to the attacking or pivot workstation.

#### Configuration Steps

1. Open Proxifier
    
2. Add new proxy server:
    

```
Address: 127.0.0.1
Port: 1080
Protocol: SOCKS5
```

3. Create rule:
    

```
Redirect all traffic → 127.0.0.1:1080
```

Result:  
All application traffic is forced through the SOCKS tunnel.

---

### 7. Pivoting Through RDP

Once Proxifier is active:

```cmd
mstsc.exe
```

Connections now flow as:

```
Local Application
 → Proxifier
 → SOCKS (127.0.0.1:1080)
 → RDP DVC Tunnel
 → 172.16.5.19
 → Internal Network
 → 172.16.6.155
```

This enables RDP access to otherwise unreachable internal hosts.

---

### 8. Performance Optimization (RDP)

Multiple RDP tunnels may cause latency.

Optimize performance:

1. Open `mstsc.exe`
    
2. Go to **Experience** tab
    
3. Set performance profile to:
    

```
Modem (Low bandwidth)
```

This disables graphical features and reduces bandwidth usage.
