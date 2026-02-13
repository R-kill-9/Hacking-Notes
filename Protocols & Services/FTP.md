**FTP** (File Transfer Protocol) is a standard network protocol used to transfer files between a client and a server over a network. 

---

## Anonymous access
**FTP** allows users to connect to an FTP server without a specific username or password. The user typically logs in using the username **"anonymous"**. This provides a convenient way to access publicly available files, like software or documentation, but it also poses several security risks if not properly controlled.

```bash
ftp> passive off
```


---

## Disable passive mode

Sometimes when listing directories or transferring files via FTP, connections may fail or stall if passive mode is enabled. Disabling passive mode forces the server to initiate data connections directly, which can resolve these issues and improve compatibility with certain firewalls or network configurations.

```bash
ftp <target_ip>
# Once Connected
username: Anonymous
password: Anonymous
```


---

## FTP Bounce Attack
An **FTP bounce attack** is a technique that abuses the FTP protocol to send network traffic to a third system through a vulnerable FTP server.

FTP normally works with two channels:

- **Control channel (TCP 21)** – used to send commands (USER, PASS, PORT, etc.)
    
- **Data channel** – used to transfer files or directory listings
    

In active mode FTP, the client uses the **PORT command** to tell the server where to send the data connection. The client specifies an IP address and a port number. The server then opens a connection to that IP and port.

The vulnerability appears when an FTP server does not properly validate the IP address provided in the PORT command.

The `Nmap` -b flag can be used to perform an FTP bounce attack:
```bash
nmap -Pn -v -n -p80 -b anonymous:password@<ftp_server_ip> <internal_target_ip>
```
Modern FTP servers include protections that, by default, prevent this type of attack, but if these features are misconfigured in modern-day FTP servers, the server can become vulnerable to an FTP Bounce attack.


---


## Brute Force Attack with Hydra
**Hydra** is a powerful password-cracking tool used for conducting **brute-force attacks** on various services, including FTP.

| Option                            | Description                                                                                                      |
|-----------------------------------|------------------------------------------------------------------------------------------------------------------|
| `-l <username>`                   | Specifies the **username** to use in the attack. You can use a single username or use a list with `-L <username_list>`. |
| `-P <password_file>`              | Specifies the **password list** (dictionary) to use for the attack. You can provide a custom list or use default wordlists like `rockyou.txt`. |
| `ftp://<target_ip>`               | Specifies the target FTP server's IP address.                                                                   |

```bash
hydra -l <username> -P <password_file> ftp://<target_ip>
```


---

## Enumeration using Metasploit
#### Version Enumeration
1. **Search for FTP Auxiliary Modules**

To begin with, we use the **search** command in Metasploit to find auxiliary modules related to FTP enumeration.

```bash
msf6 > search type:auxiliary name:ftp
```

This search command filters auxiliary modules that are related to FTP. It will return a list of available FTP-related modules, including the `ftp_version` module, which is commonly used to determine the version of an FTP server.

 2. **Using the `ftp_version` Module**

The **`ftp_version`** auxiliary module is used to gather information about the FTP server, particularly the FTP server's **version**. This can help in identifying potential vulnerabilities associated with specific versions of FTP software.

```bash
msf6 > use auxiliary/scanner/ftp/ftp_version
```

#### Login Brute Force Attack
In Metasploit, this type of attack can be performed using the `ftp_login` auxiliary module (or similar modules for different protocols). 

1.  **Search and select  the FTP Brute-Force Module**

Use the `search` command to find the `ftp_login` module or any other module related to brute-forcing FTP logins:

```bash
msf6 > search type:auxiliary name:ftp
msf6 > use auxiliary/scanner/ftp/ftp_login
```

2.  **Configure the Attack**

Configure the exploit parameters.

```bash
msf6 auxiliary(scanner/ftp/ftp_login) > set RHOSTS <target_ip>

msf6 auxiliary(scanner/ftp/ftp_login) > set RPORT <target_port>

msf6 auxiliary(scanner/ftp/ftp_login) > set USER_FILE /path/to/usernames.txt

msf6 auxiliary(scanner/ftp/ftp_login) > set PASS_FILE /path/to/passwords.txt

msf6 auxiliary(scanner/ftp/ftp_login) > run
```

