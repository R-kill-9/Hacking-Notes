## Tools Required

- Burp Suite (Community or Professional)
- Rooted Android device or emulator
- PC and mobile connected to the same Wi-Fi network


---


## 1. Configure Network and Proxy

#### Set Burp as an HTTP Proxy

1. Open Burp Suite
2. Go to `Proxy > Options > Proxy Listeners`
3. Add a new entry, for example in the port `9090` with the `All interfaces` option for **Bind to address option**.

#### Find your PC's IP address
```
ifconfig
```

## 2. Set Proxy on the Android Device

On your Android device:

1. Go to `Settings > Wi-Fi > [Your Network] > Modify Network`
2. Enable “Advanced options”
3. Set:
    - Proxy: Manual
    - Proxy hostname: your PC IP (e.g., `192.168.1.100`)
    - Proxy port: `9090`

Now all HTTP(S) traffic from the device goes through Burp.
 

---

## 3. Install Burp Certificate for HTTPS Traffic

Burp intercepts HTTPS by acting as a Man-In-The-Middle proxy. For that, you must install its CA certificate.

### Steps:

1. In Burp, go to `Proxy > Intercept > Open Browser`
2. Visit `http://burp` or `http://burpsuite` in that browser
3. Download the certificate (`cacert.der`)
4. Rename the file to `burp.cer`
5. Transfer it to your Android (e.g., `/sdcard/Download`)
6. On Android:
    - Go to `Settings > Security > Install a certificate > CA Certificate > Install anyway`

