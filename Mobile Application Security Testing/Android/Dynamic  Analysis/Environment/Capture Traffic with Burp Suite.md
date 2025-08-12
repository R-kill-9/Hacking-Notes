
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



