### 1. Enable Developer Options on Android

1. Open **Settings → About Phone**.
    
2. Locate **Build Number** (sometimes under **Software Information**).
    
3. Tap **7 times** on Build Number.
    
4. Enter your PIN or pattern if prompted.
    
5. You will see a message: _"You are now a developer!"_
    

---

### 2. Enable USB Debugging

1. Go to **Settings → System → Developer Options** (or just **Developer Options**).
    
2. Enable:
    
    - **USB Debugging**
        
    - **Install via USB** (if available)
        
    - Optional: **OEM Unlocking** (only if needed for flashing)
        
3. Connect your device to the computer via a **data-capable USB cable**.
    
4. On the device, accept the prompt _"Allow USB debugging?"_ and optionally check **Always allow from this computer**.
    

---

### 3. Verify Device Connection on Kali

1. Restart the ADB server:
```bash
adb kill-server
adb start-server
adb devices
```

2. The device should appear as:
```bash
List of devices attached
<serial_number>  device
```

3. If the device shows `unauthorized`, accept the debugging prompt on the Android device.
 

---

### 4. Troubleshooting USB Recognition

- Use a proper **data cable**, not a charging-only cable.
    
- Check USB mode on the device: select **File Transfer (MTP)**.
    
- Verify the device is detected by Linux:
```bash
lsusb
```


---

### 5. Grant App Permissions (if required)

- Find the package name of the app:

```bash
adb shell pm list packages | grep <app_name>
```

- Grant permissions via ADB:

```bash
adb shell pm grant <package_name> android.permission.CAMERA
adb shell pm grant <package_name> android.permission.READ_EXTERNAL_STORAGE
adb shell pm grant <package_name> android.permission.WRITE_EXTERNAL_STORAGE
adb shell pm grant <package_name> android.permission.ACCESS_FINE_LOCATION
```

- For rooted devices, you can grant all permissions in one command with `su`.