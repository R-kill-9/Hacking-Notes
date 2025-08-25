A **BroadcastReceiver** is an Android component that listens for **broadcast intents**. Applications may expose receivers for internal communication or inter-app messages. When a receiver is **exported** and listens for intents with extras, it can be tested to see if it is vulnerable to **input manipulation** or **permission re-delegation**.

---

## Steps to Test a BroadcastReceiver

1. **Identify the Receiver**    
    - Open `AndroidManifest.xml` and look for `<receiver>` tags.
    - Note the **receiver class** and the **intent action** it listens for.
    - Check if the receiver is `exported="true"`; this means it can be called from outside the app.
2. **Check Expected Inputs**
    - Look at the receiver’s `onReceive()` method.
    - Identify **intent extras** (e.g., strings, integers) that the receiver expects.
    - These extras may influence the app’s behavior or sensitive actions.
3. **Send a Test Broadcast via ADB**

Use the `adb shell am broadcast` command to send a broadcast with controlled values. Generic syntax:
```bash
adb shell am broadcast -a <INTENT_ACTION> --es <EXTRA_KEY1> <VALUE1> --es <EXTRA_KEY2> <VALUE2> -n <PACKAGE_NAME>/<RECEIVER_CLASS>
```

Where:

- `-a <INTENT_ACTION>` → the action defined in the receiver’s intent-filter.
    
- `--es <EXTRA_KEY> <VALUE>` → string extras to pass to the receiver (can repeat for multiple extras).
    
- `-n <PACKAGE_NAME>/<RECEIVER_CLASS>` → fully qualified receiver class in the target app.
    

Example in generic form:
```bash
adb shell am broadcast -a "com.example.ACTION_TEST" --es param1 "value1" --es param2 "value2" -n com.example.app/.ExampleReceiver
```
4. **Observe Application Behavior**

- Check logs (`adb logcat`) for exceptions or errors.
    
- See if the app performs actions based on your supplied extras.
    
- If it does, the receiver may be vulnerable to **injection or permission re-delegation**.