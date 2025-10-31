Ping sweeping is a network scanning technique used to identify active hosts on a network by sending ICMP Echo Requests (ping) to multiple IP addresses and waiting for responses. It is typically a **non-aggressive** approach, especially when done with low frequency to avoid detection.

## Ping
Tests connectivity to a host by sending ICMP Echo Requests and measuring the time taken for replies.

```bash
ping <host>
```

The flag `-c <number>` can be used to specify the number of packets that must to be send.

## Fping
Similar to ping but designed for bulk testing multiple hosts simultaneously.
- **`-a`**: Display only the hosts that are alive (responding to ping).
- **`-g`**: Specify a range of IP addresses to ping.
```bash
fping -a -g 192.168.1.0/24 2>/dev/null
```


