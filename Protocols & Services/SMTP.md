**SMTP (Simple Mail Transfer Protocol)** is a protocol used for sending and routing email messages between servers. It defines the rules for how email is transferred from the sender's email client to the recipient's mail server or between mail servers. 

## Connecting to SMTP Servers Using Netcat

You can connect to an SMTP server using **Netcat** (nc) to test its functionality or send commands. 

1. Open a terminal.
2. Run the command to connect to the SMTP server:
```bash
nc <SMTP_Server> 25
```
3. Interact with the server using SMTP commands:
```bash
# Start the conversation
HELO example.com
# Verify the existance of a user
VRFY <user_name>
# Specify the sender
MAIL FROM:<sender@example.com>
# Specify the recipient
RCPT TO:<recipient@example.com>
# Compose the message
DATA
Subject: Test Email
This is a test email sent via Netcat.
.
# End the session
QUIT
```

## Nmap Enumeration
**Nmap** can be used to scan for open SMTP ports (default 25) on the target system:

#### Identify SMTP Version

Use the `smtp-commands` script to enumerate supported commands and identify the SMTP version.

```bash
nmap -p 25,587,465 --script smtp-commands <target>
```

#### Check for Open Relays

Use the `smtp-open-relay` script to test if the server allows open relay:

```bash
nmap -p 25 --script smtp-open-relay <target>
```

#### Enumerate Users

Use the `smtp-enum-users` script to enumerate valid usernames:

```bash
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,RCPT} <target>
```

## Enumeration using Metasploit
**Metasploit** offers multiple modules for enumerating SMTP services on a target.

- **Identify SMTP Version**: Use the `smtp_version` module to identify the version of the SMTP server running on the target system. This helps determine any potential vulnerabilities related to the specific version of SMTP.
- **Enumerate SMTP Users**: Use the `smtp_enum` module to enumerate valid email addresses or users on the SMTP server. By sending specific commands (like `VRFY` or `RCPT TO`), this module helps identify existing email addresses or users that can be targeted for further attacks.