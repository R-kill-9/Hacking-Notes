**SSL Pinning** is a security mechanism that ensures the app only trusts a specific certificate or public key, protecting against MITM (Man-In-The-Middle) attacks.

If an app uses SSL pinning, Mitmproxy won't be able to intercept the HTTPS traffic, as the app will detect that the certificate does not match what it expects.

## Bypass Techniques

#### Frida (Runtime Hooking)

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

#### Objection (Frida-based CLI Tool)

Easy-to-use tool for bypassing SSL pinning.
```bash
objection --gadget <app_package> explore
android sslpinning disable
```