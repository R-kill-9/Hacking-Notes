**Fridump** is a memory dumping utility that utilizes the Frida framework to extract accessible memory regions from running processes. It is used o retrieve sensitive information such as encryption keys, passwords, or other data stored in memory.


---

## Pre-requisites
Before using Fridump, ensure the following:

- **Python**: Install Python 3.x.
- **Frida**: Install Frida and Frida-tools using pip:
```bash
pipx install frida frida-tools
```
- **Frida Server**: Download the appropriate Frida server for your device architecture from the Frida releases page.
- **Rooted Device (Android)**: For Android devices, root access is required to access process memory.
- **Jailbroken Device (iOS)**: For iOS devices, jailbreak access is necessary.


---

## Installation
To install Fridump you just need to clone it from git and run it:
```bash
python3 -m venv venv
source venv/bin/activate
git clone https://github.com/Nightbringer21/fridump.git
python fridump.py -h
```


---

## Usage

#### Android

1. Push the Frida server to the device and set appropriate permissions:
```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```
2. Identify the target application's process name:
```bash
frida-ps -U
```
3. Dump the application's memory:
```bash
python fridump.py -U -s <process_name>
```

#### iOS

1. Connect the iOS device via USB.
2. Identify the target application's process name:
```bash
frida-ps -Uai
```
3. Dump the application's memory:
```bash
python fridump.py -U -s <process_name>
```


---

## Analyzing the Dump

- **Output Files**: Fridump generates binary dump files named like `0x1a7400000_dump.data`.

- **Strings Extraction**: Use the `strings` command to extract readable strings from the dump files:

```bash
strings <dump_file> > strings.txt
```

- **Automated Strings Extraction**: Use the `-s` flag with Fridump to automatically extract strings:
```bash
  python fridump.py -U -s <process_name>
```