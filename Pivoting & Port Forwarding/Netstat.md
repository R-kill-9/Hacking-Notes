**Netstat** (Network Statistics) is a command-line tool to display network connections, routing tables, and interface statistics. It can be useful to find open ports to execute a port forwarding.

#### **Key Flags**

| Option | Description |
|--------|-------------|
| **`-a`** | Show all connections and listening ports. |
| **`-n`** | Show numerical addresses and port numbers (no DNS resolution). |
| **`-t`** | Display TCP connections. |
| **`-u`** | Display UDP connections. |
| **`-l`** | Show only listening ports. |
| **`-p`** | Show the PID/program name associated with each connection. |
### **Basic Commands**

- **Show active connections**:
```bash
netstat -an
```
- **List listening ports**:
```bash
netstat -tuln
```




