Root detection is commonly implemented in mobile applications to prevent execution on rooted devices. To bypass this mechanism, an attacker can analyze the application code to identify and disable the detection logic.

---

## Recompile APK

1. **Decompile the APK** to review the application code.
```bash
apktool d target.apk -o target_decoded
```

2. **Locate root detection functions**

- Search for method names or strings such as:
```bash
isDeviceRooted
checkSuExists
detectRoot
su
/system/xbin
/system/bin
```

3. **Modify or remove the detection logic**
    - Comment out or bypass function calls.
    - Change the return value to always indicate "not rooted".

4. **Rebuild and sign the APK**
```bash
apktool b target_decoded -o patched.apk
jarsigner -keystore mykeystore.jks patched.apk alias_name
```


---

## Bypass using Hooking 
Instead of modifying the APK, runtime hooking can be used to bypass root detection without rebuilding.

#### Using Frida

1. Start Frida server on the device.
2. Attach to the target process and hook the detection function:

```java
Java.perform(function() {
    var targetClass = Java.use("com.example.security.RootCheck");
    targetClass.isDeviceRooted.implementation = function() {
        return false;
    };
});
```