**SSL Pinning** is a security mechanism that ensures the app only trusts a specific certificate or public key, protecting against MITM (Man-In-The-Middle) attacks.

If an app uses SSL pinning, Burp won't be able to intercept the HTTPS traffic, as the app will detect that the certificate does not match what it expects.

## APK-MITM
**APK-MITM** is a tool designed to automate the process of bypassing SSL pinning in Android applications by modifying the APK directly.

#### How APK-MITM works

1. **Decompile APK** — extracts app code and resources.
2. **Patch SSL pinning logic** — modifies specific classes/methods responsible for certificate validation.
3. **Rebuild APK** — repackages the app.
4. **Sign APK** — with a debug or custom key to allow installation.
5. **Install patched APK** on the device.


#### Usage

**Step 1: Install APK-MITM**

You need Python 3 and Git installed. Then:
```bash
git clone https://github.com/sensepost/apk-mitm.git
cd apk-mitm
pip3 install -r requirements.txt
python3 apk-mitm.py -h
``` 

**Step 2: Patch an APK**

This command will:

- Decompile the APK.
- Patch SSL pinning code.
- Rebuild and sign the APK.
- Save the patched APK in the specified output directory.
```bash
python3 apk-mitm.py -i /path/to/original.apk -o /path/to/output/dir
``` 

**Step 3: Install the patched APK**

Before intalling the patched APK, make sure that the original APK has been uninstalled.
```bash
adb install -r /path/to/output/dir/patched.apk
``` 


---

## Frida (Runtime Hooking)

Frida can hook SSL functions and bypass certificate checks.

**Steps:**

- Connect the device:
```bash
frida -U -n <package_name> -l bypass-ssl.js
```

**Example Script (Java SSL Pinning Bypass):**
```javascript
Java.perform(function () {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
        console.log('[!] SSL Pinning bypassed');
        return;
    };
});
```
