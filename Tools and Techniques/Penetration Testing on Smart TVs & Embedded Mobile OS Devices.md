Embedded devices such as Smart TVs, set-top boxes, and IoT devices often run lightweight operating systems derived from Linux, Android, or proprietary OSes. Security testing involves both **network-level analysis** and **device-level analysis**.

Key objectives:

- Identify open ports and network services
- Extract firmware for static analysis
- Perform dynamic analysis to detect runtime vulnerabilities
- Assess application security (apps running on the device)


---

## Network Discovery

Many embedded devices expose services over the local network. The first step is **network scanning**.

#### Scan for open ports

Use `nmap` to detect devices with specific open ports. For example, port **5555** is commonly used for **ADB over network** on Android-based devices:
```bash
nmap -p 5555 --open 192.168.1.0/24
```

Once devices are identified, you can attempt **ADB connections** or other network services exposed by the device.

---
## Firmware Analysis

#### Extracting firmware

- Download firmware from the vendor or directly from the device.
- Use tools such as `binwalk`, `firmware-mod-kit`, or `7z` for extraction:
```bash
binwalk -e firmware.bin
```

#### Static analysis

- Inspect configuration files, certificates, or scripts for sensitive information.
- Identify hardcoded credentials or keys.


---

## Dynamic Analysis

Dynamic testing involves interacting with the device while it is running. Common steps:

- Connect to exposed services (SSH, Telnet, ADB)
- Monitor logs and network traffic
- Test app behavior in runtime using frameworks like **Frida** or **Objection** for Android-based systems.


Example: connecting to an Android-based Smart TV over ADB:
```bash
adb connect 192.168.1.105:5555
adb shell
```
Once connected, you can:

- List installed packages:
```bash
pm list packages
```

- Inspect running processes:
```bash
ps -A
```

- Pull sensitive files:
```bash
adb pull /data/data/com.example.app/shared_prefs/config.xml ./config.xml
```

