
## Manual Proxy Configuration via Android Wi-Fi Settings
####  1. Configure Network and Proxy

**Set Burp as an HTTP Proxy**

1. Open Burp Suite
2. Go to `Proxy > Options > Proxy Listeners`
3. Add a new entry, for example in the port `9090` with the `All interfaces` option for **Bind to address option**.

**Find your PC's IP address**
```bash
ifconfig
```

#### 2. Set Proxy on the Android Device

On your Android device:

1. Go to `Settings > Wi-Fi > [Your Network] > Modify Network`
2. Enable “Advanced options”
3. Set:
    - Proxy: Manual
    - Proxy hostname: your PC IP (e.g., `192.168.1.100`)
    - Proxy port: `9090`

Now all HTTP(S) traffic from the device goes through Burp.
 

#### 3. Install Burp Certificate for HTTPS Traffic

Burp intercepts HTTPS by acting as a Man-In-The-Middle proxy. For that, you must install its CA certificate.

**Steps:**

1. In Burp, go to `Proxy > Intercept > Open Browser`
2. Visit `http://burp` or `http://burpsuite` in that browser
3. Download the certificate (`cacert.der`)
4. Rename the file to `burp.cer`
5. Transfer it to your Android (e.g., `/sdcard/Download`)
6. On Android:
    - Go to `Settings > Security > Install a certificate > CA Certificate > Install anyway`


---


## Setting Global HTTP Proxy via ADB
Before setting the global proxy, make sure that Burp Suite is configured correctly. In Burp Suite, go to **Proxy > Options > Proxy Listeners** and verify that the IP address and port match the ones you will set on the Android device. Otherwise, traffic will not be intercepted.

This command sets a **global HTTP proxy** on the Android device, forcing all HTTP traffic to route through the specified proxy server (usually your PC running Burp Suite).

```bash
adb shell settings put global http_proxy <PC_IP>:<PORT>
```

Example:
```bash
adb shell settings put global http_proxy 10.160.0.61:8080
```

This approach configures the proxy at the system level, so all apps that respect the system proxy settings will send traffic through Burp.

It requires no manual configuration on the device's Wi-Fi settings, making it faster to apply, especially on emulators or rooted devices.


---

## Troubleshooting: Proxy & Certificate Issues 



- HTTPS requests do not appear in Burp even though the proxy is configured.
- The device installs Burp’s CA certificate, but apps still show TLS errors or ignore the proxy.
- Only the browser traffic is captured; third-party apps are not.



#### Root Causes (most common)

1. **Android 7+ trust model**: Apps **do not trust user-installed CAs** by default. Only the system trust store is trusted unless the app explicitly opts in via `network_security_config`.
    
2. **Certificate pinning** in the target app (e.g., OkHttp, TrustManager, native pinning).
    
3. **Proxy not actually applied** (wrong IP/port, proxy set on different Wi-Fi, global proxy not honored, firewall).
    
4. **App bypasses system proxy** (direct sockets, custom DNS, QUIC/HTTP3).
    
5. **Certificate format/placement** issues (DER vs PEM, wrong path/permissions when installing to system store).


#### Possible Solutions

**Patch the APK (Android 7+ user CAs)**

Use **apk-mitm** to make the app trust user CAs and (often) disable pinning.

**Steps**

1. Extract APK:
```bash
adb shell pm path com.target.app
adb pull /data/app/<package>-<suffix>/base.apk app.apk
```

2. Patch:
```bash
npx apk-mitm app.apk
```

This injects a **network_security_config** to trust user CAs and applies common pinning bypasses.

3. Install:
```bash
adb install -r app-patched.apk
```

4. Set proxy (Wi-Fi or global) and test in Burp.

- If the app enforces integrity checks/Play Integrity, it may detect repackaging.
- If patching fails (e.g., native pinning), use Frida (below).



**Install Burp CA into the system trust store**

1. Export Burp CA as DER and convert to PEM:

```bash
openssl x509 -inform DER -in cacert.der -out burp.pem
```

2. Compute legacy subject hash and rename:

```bash
openssl x509 -inform PEM -subject_hash_old -in burp.pem -noout
# suppose it prints: 9a5ba575
cp burp.pem 9a5ba575.0
```

3. Push to system CA directory with correct perms:
```bash
adb root
adb remount
adb push 9a5ba575.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0
adb shell chown root:root /system/etc/security/cacerts/9a5ba575.0
adb reboot
```

- On many physical devices, `/system` is read-only; use Magisk or a systemless approach to place the cert.

- Verify after reboot: the app traffic should now trust Burp’s CA.