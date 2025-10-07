> Notes copied from the original [Github Certipy](https://github.com/ly4k/Certipy/wiki/04-%E2%80%90-Installation) repository

Certipy is a Python tool that supports **Python 3.12+** and runs on both Linux and Windows. The tool is distributed via pip (Python Package Index) as `certipy-ad`. Ensure you have a suitable Python environment before installation. Below are installation instructions for common platforms:

## Linux Installation (Debian/Ubuntu/Kali)

[](https://github.com/ly4k/Certipy/wiki/04-%E2%80%90-Installation#-linux-installation-debianubuntukali)

- **Install Python 3.12+ and pip** if not already present. For example, on Debian-based systems:
    
    ```shell
    sudo apt update && sudo apt install -y python3 python3-pip
    ```
    

**Create and activate a virtual environment** (optional but recommended):

```shell
python3 -m venv certipy-venv
source certipy-venv/bin/activate
```

- This ensures Certipy's dependencies won't conflict with your system Python packages.
    
- **Install Certipy via pip**:
    
    ```shell
    pip install certipy-ad
    ```
    

1. This will download and install Certipy and its requirements (like `impacket`, `ldap3`, etc.). You should then have the `certipy` command available.
    

**Kali Linux Note:** Kali includes Certipy in its package repo as `certipy-ad`. It may be pre-installed on recent Kali releases. If so, you can directly run `certipy-ad` (Kali's packaged command name). If you wish to use the latest version via pip (which may be newer than Kali's package), use the pip method above. _(The Kali pre-installed version might require invoking `certipy-ad` instead of `certipy`.)_