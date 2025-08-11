**Drozer** allows interaction with Android applications and devices to identify vulnerabilities, exploit insecure components, and assess the security posture of apps. It is especially useful for analyzing **Inter-Process Communication (IPC)** mechanisms such as exported activities, services and content providers.

Drozer works without requiring root, making it suitable for testing on both rooted and non-rooted devices.

---

## Installation

Drozer consists of two parts:

- **Drozer Console** (runs on the tester’s machine)
- **Drozer Agent** (Android app installed on the target device)

#### Install Drozer Console (Kali/Debian-based)
```bash
sudo apt update
sudo apt install drozer
```

If the package is unavailable in repositories:
```bash
pipx install drozer
```

#### Install Drozer Agent (on the device)

- Download the APK from the official Drozer GitHub releases or archived site.
- Install on the device:
```bash
adb install drozer-agent.apk
```

---

## Starting Drozer

#### On the device

1. Launch the Drozer Agent app.

2. Enable embedded server.

3. Set to listen on `tcp/31415` by default.


#### On the tester machine

Forward Drozer port via ADB:
```bash
adb forward tcp:31415 tcp:31415
```

Connect to the device:
```bash
drozer console connect
```


---


## Common Usage

Drozer is module-based. Modules can enumerate app components, exploit exported activities/services, and interact with content providers.

**Listing Installed Packages**

```bash
run app.package.list
```

**Get Info on a Specific Package**
```bash
run app.package.info -a com.example.targetapp
```

**Enumerate Exported Activities**
```bash
run app.activity.info -a com.example.targetapp
```

**Launch an Exported Activity**
```bash
run app.activity.start --component com.example.targetapp com.example.targetapp.ActivityName
```

**Enumerate Content Providers**
```bash
run app.provider.info -a com.example.targetapp
```

**Query a Content Provider**
```bash
run app.provider.query content://com.example.targetapp.provider/table_name
```

**Exploit SQL Injection in a Content Provider**
```bash
run scanner.provider.injection -a com.example.targetapp
```