**SNMP** is a protocol that runs in **UDP** port **161** that is used for network management, monitoring, and controlling devices such as routers, switches, servers, and printers. It allows administrators to gather valuable information about devices and networks, as well as configure and troubleshoot devices remotely.

## General Infomation
- **Versions of SNMP**:
    
    - **SNMPv1**: Basic version with minimal security (community strings).
    - **SNMPv2c**: Enhanced performance but still lacks strong security.
    - **SNMPv3**: Introduced authentication and encryption for better security.
- **Components of SNMP**:
    
    - **Manager**: A system that controls and monitors SNMP devices (e.g., network management software).
    - **Agent**: Software on the device that collects and reports information back to the manager.
    - **MIB (Management Information Base)**: A database defining what data the manager can query from the agent.

## Enumeration and Scanning Using Nmap

**Nmap** can be used to perform SNMP enumeration by scanning the SNMP service (usually on port 161) and using scripts to gather detailed information from SNMP-enabled devices.

**Scan for SNMP Service (Port 161) with Version and Script Detection**

This command scans for the SNMP service on port 161 and detects its version and available scripts. It provides details about the SNMP service, such as the version running on the target device.
```bash
nmap -sU -sCV -p 161 <target>
```

**Perform a Brute Force Attack on SNMP Community Strings**

This command uses the `snmp-brute` Nmap script to attempt brute-forcing common SNMP community strings (like `public`, `private`, and others). If successful, it reveals **valid community strings** that can be used to query the device.
```bash
nmap -sU -p 161 --script snmp-brute <target>
```

**Scan SNMP with Built-in Nmap Scripts**

This command runs all available Nmap SNMP-related scripts (`snmp-*`) to gather detailed information from the target device. If SNMP is improperly configured, this scan can provide an attacker with a comprehensive view of the target device, potentially revealing sensitive information such as device names, usernames, network configurations, and even passwords in some cases.
```bash
nmap -sU -p 161 --script snmp-* <target> > snmp_info
```

### SNMP Walk 

The **snmpwalk** command can be used to retrieve information from an SNMP-enabled device. It queries the device using the SNMP protocol and returns a list of available OIDs (Object Identifiers), which can provide detailed information about the device’s configuration and status.

- **`-v 1`**: Specifies SNMP version 1.
- **`-c public`**: Specifies the community string (`public` is the default read-only community string).

```bash
snmpwalk -v 1 -c public <target>
```