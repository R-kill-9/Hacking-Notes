Rooting an Android device gives you full control over the operating system. As a penetration tester or mobile security researcher, rooting allows you to:

- Access restricted system files and directories.

- Use tools like **Frida**, **Objection**, or **Burp** with full permissions.

- Bypass app restrictions or protections.

- Analyze app behavior at a deeper level (dynamic analysis).

> Instead of this guide, you can use this Youtube tutorial: https://www.youtube.com/watch?v=EsQ_0KvSHf0

---

## 1. Understanding Key Concepts

#### Bootloader

The **bootloader** is a program that runs before the Android OS starts. It verifies the system image to ensure it hasn't been tampered with.

To modify the device (install custom firmware, root, etc.), you must **unlock the bootloader**.

### boot.img

The **boot.img** file contains the Linux kernel and the initial RAM disk (initrd). This image is loaded at boot and controls how the system starts. **Magisk modifies this image** to inject root access without altering the main system partition.

#### ADB (Android Debug Bridge)

**ADB** is a command-line tool that allows you to communicate with an Android device from a PC. It is used for debugging, transferring files, and performing various commands such as rebooting into bootloader mode.

#### Fastboot

**Fastboot** is a protocol that allows you to flash images (like `boot.img`) to an Android device. It operates when the device is in bootloader mode and is used to modify partitions directly.

#### TWRP (Team Win Recovery Project)

**TWRP** is a custom recovery that replaces the stock recovery on your device. It allows you to flash ZIP or IMG files, create full backups, and make modifications to the system using a touch-based interface.

---

## 2. Requirements

Before starting, you need:

- An Android device (test device, not your main phone).

- USB cable.

- A computer (Windows, macOS, or Linux).

- [ADB and Fastboot](https://developer.android.com/tools/releases/platform-tools) installed.

- Magisk (latest release).

- Custom recovery like TWRP (specific to your device).

- The official firmware of your device (for extracting the original `boot.img`).


---

## 3. Rooting Process with Magisk
The bootloader prevents modifications to the system. To flash Magisk (modifying `boot.img`), the bootloader must be unlocked first.

### Step 1: Unlock the Bootloader

1. Enable **Developer Options**:
    
    - Go to _Settings > About Phone > Tap “Build number” seven times_.
        
2. Enable **OEM Unlocking** and **USB Debugging**:
    
    - _Settings > System > Developer Options_
        
    - Toggle on both settings.
        
3. Connect your phone to your PC via USB.
    
4. Reboot to bootloader:
```
adb reboot bootloader
```
5. Unlock the bootloader:
```
fastboot flashing unlock
```
- Some devices may use `fastboot oem unlock` instead.
- On your phone, confirm the unlock when prompted.
> This process will wipe all your data.


---
### Step 2: Extract and Patch boot.img

1. Download the stock firmware (same Android version your phone is using).
    
    - Usually provided as a ZIP file or `.tar` by the manufacturer.
        
    - Extract the `boot.img` from the package.
        
2. Transfer `boot.img` to your phone (e.g., Downloads folder).
    
3. Install **Magisk APK** on your phone (from [GitHub releases](https://github.com/topjohnwu/Magisk)).
    
4. Open Magisk, tap _Install > Select and Patch a File_, and choose `boot.img`.
    
5. Wait until Magisk finishes patching. It will generate a file called:
```
magisk_patched-[random].img
```
Usually saved in `/Download`.


---

### Step 3: Flash the Patched Boot Image

1. Transfer the patched image back to your PC:
```
adb pull /sdcard/Download/magisk_patched-XXXX.img
```
2. Reboot to bootloader again:
```
adb reboot bootloader
```
3. Flash the patched image:
```
fastboot flash boot magisk_patched-XXXX.img
```
4. Reboot the phone:
```
fastboot reboot
```


----
## 4. Verifying Root Access

#### Method 1: Using Root Checker App

1. Install **Root Checker** from the Play Store.

2. Open it and tap “Verify Root”.

3. If successful, you’ll see a message like “Root access is properly installed”.


#### Method 2: Using Root Browser

1. Install **Root Browser** or **Mixplorer (with root support)**.

2. Try browsing to:

- `/system/`

- `/data/`

- `/data/data/`

3. If the app can read/write in these folders, root is active.