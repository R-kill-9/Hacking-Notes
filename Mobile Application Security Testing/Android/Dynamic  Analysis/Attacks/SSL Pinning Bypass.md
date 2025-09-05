**SSL Pinning** is a security mechanism that ensures the app only trusts a specific certificate or public key, protecting against MITM (Man-In-The-Middle) attacks.

If an app uses SSL pinning, Burp won't be able to intercept the HTTPS traffic, as the app will detect that the certificate does not match what it expects.


## Frida 

> Check this content for useful scripts: [Frida CodeShare](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)

1. Start a shell on the device or emulator and gain root
```bash
adb shell
su
```

2. Start the Frida server
```bash
cd /data/local/tmp
./frida-server-17.2.17-android-x86_64
```

3. Push the Burp Suite CA certificate to the device and set correct permissions

- Download your Burp Suite CA certificate (e.g., `cert.der`).
    
- Move it to the exact location expected by the Frida script:
```bash
adb push cert.der /data/local/tmp
adb shell
su
cd /data/local/tmp
mv cert.der cert-der.crt
chmod 755 cert-der.crt
```

4. Run the SSL pinning bypass using Frida

- `-U` connects to the USB device/emulator.
- `--codeshare` loads the published Frida script for bypassing SSL pinning    
- `-f <package>` spawns the target app.

```bash
frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f infosecadventures.allsafe
```

Expected output:
```bash
[+] Loading our CA...
[+] Creating a TrustManager that trusts the CA...
[+] SSLContext initialized with our custom TrustManager!
```


---

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



