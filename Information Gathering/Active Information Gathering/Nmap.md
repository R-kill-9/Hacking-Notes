 **Nmap (Network Mapper)**  allows users to scan networks, identify hosts, and determine open ports, services, and operating systems running on devices.

| Option               | Description                                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **`-sV`**            | Shows the version of the service running on each port.                                                                          |
| **`-sC`**            | Uses additional scripts to gather more information.                                                                             |
| **`-sS`**            | Stealth scan.                                                                                                                   |
| **`-sn`**            | Is used for a ping scan.                                                                                                        |
| **`-sU`**            | Scans the UDP ports.                                                                                                            |
| **`-sT`**            | Makes the scan by TCP.                                                                                                          |
| **`-p-`**            | Scans all ports.                                                                                                                |
| **`-Pn`**            | Skip recognition phase.                                                                                                         |
| **`-O`**             | Determines the operating system of the target.                                                                                  |
| **`-p <port>`**      | Scans only the specified port number.                                                                                           |
| **`-vvv`**           | Increase verbosity.                                                                                                             |
| **`--open`**         | Only displays open ports.                                                                                                       |
| **`-iL`**            | Allows you to specify a file containing a list of IP addresses.                                                                 |
| **`-PS`**            | Sends TCP SYN packets to determine if a host is up. It's useful for network discovery when ICMP (ping) is blocked by firewalls. |
| **`--osscan-guess`** | Allows to make a guess of the operating system.                                                                                 |
| **`--min-rate`**     | Specifies the minimum number of packets Nmap should send per second; increasing this number speeds up the scan.                 |
| **`-T[0...5]`**      | Sets the timing template, which controls the speed and aggressiveness of the scan.                                              |
| **`-oN,-oG,-oX`**    | Saves the scan results in a human-readable plain text format (-oN), in XML format (-oX), or in grepable format (-oG).           |


```bash
nmap  -sS -sCV -p21 <ip_address>
```

## Nmap scripts
In Kali Linux, **Nmap scripts** are located in the directory:   `/usr/share/nmap/scripts/`

These scripts, part of the **Nmap Scripting Engine (NSE)**, extend Nmap's functionality. They allow users to perform tasks such as:

- Vulnerability detection.
- Service enumeration.
- Brute-forcing.
- Exploiting specific vulnerabilities.

```bash
nmap --script <script-name> <target>
```

To understand what a specific **Nmap NSE script** does, you can use the `--script-help` option followed by the script's name.

```bash
nmap --script-help <script-name>
```

Use the `--script-args` flag to supply arguments to a script during an Nmap scan.

```bash
nmap --script <script-name> --script-args <argument1>=<value1>,<argument2>=<value2> <target>
```