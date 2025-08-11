Frida consists of two main components:

1. **Frida tools** (client) on your **host machine** (Linux, macOS, or Windows).
2. **Frida server** (agent) on the **target Android device** (must be rooted).

#### Install Frida Tools on Host
Use Python’s package manager:
```bash
pip install frida-tools
``` 

#### Download Frida Server for Android

1. Go to the [official Frida releases](https://github.com/frida/frida/releases).

2. Download the correct `frida-server` binary for your Android device's architecture:

Examples:

- ARM64 → `frida-server-<version>-android-arm64.xz`
- ARMv7 → `frida-server-<version>-android-arm.xz`

3. Extract the `.xz` file:
```bash
xz -d frida-server-*.xz
chmod +x frida-server-*
``` 

#### Push Frida Server to Android Device

Connect your device via ADB:
```bash
adb push frida-server-* /data/local/tmp/
adb shell
cd /data/local/tmp
chmod 755 frida-server-*
``` 

#### Run Frida Server on Device

Inside the ADB shell:
```bash
su  # switch to root
./frida-server-<version>-android-arm64 &
``` 
Use `ps -A | grep frida` to check if it’s running.

#### Connect and Test from Host

List running apps:

```bash
frida-ps -U
``` 