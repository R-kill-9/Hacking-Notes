To interact with a real mobile device or an emulator, you need to connect your **physical device via USB** or **start an emulator**. Once done, ADB (Android Debug Bridge) can be used to send commands directly.

## ADB Components

ADB consists of **three components**:

- **Client**: Runs on your machine and sends commands.
- **Server**: Manages communication between the client and the daemon.
- **Daemon (adbd)**: Runs on the emulator or connected device and executes commands.

## Accessing the Shell

You can execute commands in two ways:

- **Start an interactive shell session**:
```bash
adb shell
``` 

Then type commands like:
```bash
ls -la
``` 

- **Run commands directly in one line**:
```bash
adb shell ls -la
``` 

> The difference is that the first opens a persistent shell, while the second executes the command and returns.

## Common ADB Commands
| Command                                  | Description                                      |
| ---------------------------------------- | ------------------------------------------------ |
| `adb devices`                            | Lists all connected devices and emulators        |
| `adb shell`                              | Opens an interactive shell session on the device |
| `adb shell <cmd>`                        | Executes `<cmd>` directly in the shell           |
| `adb shell pm list packages`             | Lists all installed packages on the device       |
| `adb shell pm path <package_name>`       | Shows the path of the installed package          |
| `adb shell am start -n <pkg>/<activity>` | Starts a specific activity                       |
| `adb shell am startservice <intent>`     | Starts a background service                      |
| `adb shell am broadcast <intent>`        | Sends a broadcast intent                         |
| `adb shell input <keyevent/text>`        | Simulates user input (touch, typing, etc.)       |
| `adb pull <remote> <local>`              | Copies a file from the device to your computer   |
| `adb push <local> <remote>`              | Copies a file from your computer to the device   |
| `adb install <apk_file>`                 | Installs an APK on the device                    |
| `adb uninstall <package_name>`           | Uninstalls an app                                |
| `exit`                                   | Exits the interactive shell session              |
#### ADB Input Examples
|Command|Action|
|---|---|
|`adb shell input text 'hello%sworld'`|Types "hello world"|
|`adb shell input keyevent 66`|Presses "Enter" key|
|`adb shell input tap 500 800`|Simulates tap at (500, 800)|
|`adb shell input swipe 300 1000 300 500`|Swipes up|