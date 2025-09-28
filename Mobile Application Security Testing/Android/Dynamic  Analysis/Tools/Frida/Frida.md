**Frida** is a powerful framework for hooking into live processes and modifying their behavior at runtime.  

## Installation
1. **Frida tools** (client) on your **host machine** (Linux, macOS, or Windows).
2. **Frida server** (agent) on the **target Android device** (must be rooted).

#### Install Frida Tools on Host
Use Python’s package manager:
```bash
pipx install frida-tools
``` 

#### Download Frida Server for Android

1. Go to the [official Frida releases](https://github.com/frida/frida/releases).
2. Download the correct `frida-server` binary for your Android device's architecture:

**Examples:**

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

## Usage
1. **Identify your target device** using `frida-ls-devices` to ensure your device is detected.
2. **Find the target app or process** by listing running processes with `frida-ps -U`.
3. **Write your hook script** in JavaScript (`hook.js`), specifying what functions or behaviors to intercept or modify.
```js
Java.perform(function () {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkServerTrusted.implementation = function () {
        console.log('SSL Pinning bypassed!');
        return;
    };
});
```
4. **Attach to a running app** or spawn it with your hook preloaded:
- Attach to running process:
```bash
frida -U -n <process_name> -l hook.js
``` 
- Spawn app with hook:
```bash
frida -U -f com.example.app -l hook.js 
``` 
5. **Monitor output** from your script and adjust as needed.
6. **Iterate** on your hook script to expand capabilities or refine what you intercept.
#### Useful flags
| Flag               | Description                                       |
| ------------------ | ------------------------------------------------- |
| `-U`               | Connect to USB device (via ADB)                   |
| `-n <name>`        | Attach to a running process by name               |
| `-p <pid>`         | Attach to a running process by PID                |
| `-f <app>`         | Spawn a new process (app) by package name         |
| `-l <file>`        | Load and run the specified JavaScript hook script |
| `--no-pause`       | Resume the spawned app immediately (do not pause) |
| `-o <file>`        | Redirect output to a file                         |
| `--runtime=<type>` | Specify JavaScript runtime (`v8`, `duk`)          |
| `-h`, `--help`     | Show help information                             |
#### Hook multiple functions at once

When reversing Android apps you often need to patch many small checks (root checks, signature checks, feature flags, etc.). Instead of writing repetitive `targetClass.method.implementation` blocks, you can hook multiple functions at once with concise helpers and patterns. 

```js
// Root Bypass
Java.perform(function() {
var targetClass = Java.use('sg.vantagepoint.util.RootDetection');

targetClass.checkRoot1.implementation = function() {
console.log('Bypassing root check in checkRoot1()');
return false; // Always return false
};

targetClass.checkRoot2.implementation = function() {
console.log('Bypassing root check in checkRoot2()');
return false; // Always return false
};

targetClass.checkRoot3.implementation = function() {
console.log('Bypassing root check in checkRoot3()');
return false; // Always return false
};

});


// Debug Bypass
Java.perform(function() {
var targetClass = Java.use('sg.vantagepoint.util.IntegrityCheck');

targetClass.isDebuggable.implementation = function() {
console.log('Bypassing Integrity Check');
return false; // Always return false
};
});

``` 
