fter gaining initial access to a target system, the obtained shell is often **non‑interactive** or **restricted** (sometimes referred to as a _limited shell_ or _jail shell_).  
Such shells may lack:

- Job control
    
- Tab completion
    
- Signal handling (Ctrl+C, Ctrl+Z)
    
- A proper command prompt
    

To improve usability, it is common to **spawn an interactive shell** using binaries or scripting languages available on the system.


---

## Using /bin/sh Directly

```bash
/bin/sh -i
```

- `-i` enables **interactive mode**
    
- Provides a prompt and basic job control (limited)

---

## Language-Based Shell Spawning

If common scripting languages are installed, they can be used to execute a shell interpreter.

### Perl

Execute directly from the command line:

```bash
perl -e 'exec "/bin/sh";'
```

From a script:

```perl
exec "/bin/sh";
```


### Ruby

From a script:

```ruby
exec "/bin/sh"
```


### Lua

Using the `os.execute` function:

```lua
os.execute('/bin/sh')
```

Must be executed within a Lua interpreter or script.

---

## AWK-Based Shell

AWK is commonly available on Unix/Linux systems and can execute system commands.

```bash
awk 'BEGIN {system("/bin/sh")}'
```

This spawns a shell by invoking `/bin/sh` through AWK’s `system()` function.

---

## Using find to Spawn a Shell

### Using AWK via find

```bash
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

- Searches for a file named `nameoffile`
    
- Executes AWK, which then spawns `/bin/sh`
    

### Executing Shell Directly

```bash
find . -exec /bin/sh \; -quit
```

- Uses `-exec` to launch `/bin/sh`
    
- `-quit` stops execution after the first match
    
- If `find` fails to match, no shell is spawned
    

---

## VIM-Based Shell Escape

If VIM is accessible, it can be abused to spawn a shell.

### One‑liner

```bash
vim -c ':!/bin/sh'
```

### From Inside VIM

```vim
:set shell=/bin/sh
:shell
```

This replaces VIM’s shell and spawns it interactively.

---

## Permission Considerations

Spawning an interactive shell depends on **execution permissions** and **user privileges**.

### Checking File Permissions

```bash
ls -la <path/to/file_or_binary>
```

Used to verify whether a binary is executable by the current user.


### Checking sudo Privileges

```bash
sudo -l
```

Example output:

```
Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

This indicates the user can run commands as root without a password, enabling privilege escalation.