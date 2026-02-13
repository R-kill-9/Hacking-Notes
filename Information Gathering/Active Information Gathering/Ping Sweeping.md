Ping sweeping is a network scanning technique used to identify active hosts on a network by sending ICMP Echo Requests (ping) to multiple IP addresses and waiting for responses. It is typically a non‑aggressive approach, especially when done with low frequency to avoid detection.

---

## Ping

Tests connectivity to a host by sending ICMP Echo Requests and measuring the time taken for replies.

```bash
ping <host>
```

The flag `-c <number>` can be used to specify the number of packets that must be sent.

---

## Fping

Similar to ping but designed for bulk testing multiple hosts simultaneously.

- **`-a`**: Display only the hosts that are alive (responding to ping).
    
- **`-g`**: Specify a range of IP addresses to ping.
    

```bash
fping -a -g 192.168.1.0/24 2>/dev/null
```

---
## Meterpreter Ping Sweep

Meterpreter provides a built‑in module to identify reachable hosts from an internal network.

```bash
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

This sends ICMP requests from the compromised system instead of the attacker machine.

---

## Ping Sweep Using a Linux Pivot Host

A simple bash loop can enumerate active hosts in a subnet:

```bash
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &) ; done
```

- Sends one ICMP packet per host
    
- Displays only responsive systems
    

---

## Ping Sweep Using Windows CMD

```cmd
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

- `-n 1` → send one packet
    
- `-w 100` → short timeout to speed up scanning
    

---

## Ping Sweep Using PowerShell

```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

Uses `Test-Connection` to quickly verify host availability and returns boolean results.
