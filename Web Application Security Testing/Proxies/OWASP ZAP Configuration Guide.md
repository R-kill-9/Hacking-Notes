## 1. Installation and Prerequisites

Before configuring OWASP ZAP, ensure that:

- **Java 11 or higher** is installed (ZAP runs on Java).
- The latest version of **OWASP ZAP** is downloaded from the official website.
- You have the necessary permissions to modify browser and network settings.

---

## 2. Setting Up the OWASP ZAP Proxy

OWASP ZAP functions as an **intercepting proxy**, allowing you to analyze and manipulate HTTP/S traffic between the browser and the web server.

#### 2.1 Manual Proxy Configuration in ZAP

1. Open OWASP ZAP.
2. Navigate to **Tools > Options > Local Proxies**.
3. Ensure the proxy is enabled and listening on an accessible address and port (default: `127.0.0.1:8080`).
4. If necessary, change the port to avoid conflicts with other services.

#### 2.2 Configuring the Proxy in the Browser

To capture traffic, configure your browser to use ZAP as a proxy.

**Firefox:**
1. Go to **Settings > General > Network Settings > Configure Proxy**.
2. Select **Manual proxy configuration**.
3. Enter:
    - **HTTP Proxy**: `127.0.0.1`
    - **Port**: `8080` (or the port set in ZAP).
4. Check **Use this proxy server for all protocols**.
5. Save the changes.

**Chrome (via system settings or extension):**

1. Open **chrome://settings** in the address bar.
2. Go to **Advanced > System > Open your computer’s proxy settings**.
3. Configure the proxy to **127.0.0.1:8080**.


---

## 3. Using a PAC (Proxy Auto-Config) File

Instead of manually setting the proxy, you can use a **PAC file** to automatically configure proxy settings based on URL rules.

1. **Create a `.pac` file** with the following content:
```javascript
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.example.com")) {
        return "PROXY 127.0.0.1:8080";
    }
    return "DIRECT";
}
```
> This sends only `example.com` traffic through OWASP ZAP while other traffic bypasses the proxy.

2. **Load the PAC file in your browser:**

- In Firefox: **Settings > General > Network Settings > Auto-configure Proxy URL**.
- In Chrome: Start Chrome with this argument:
```bash
chrome --proxy-pac-url=file:///path/to/proxy.pac
```


---

## 4. Configuring SSL/TLS Certificates in OWASP ZAP

To intercept **HTTPS traffic**, ZAP requires its **root CA certificate** to be installed in the browser or operating system.

### 4.1 Exporting the OWASP ZAP Certificate

1. Open OWASP ZAP.
2. Go to **Tools > Options > Dynamic SSL Certificates**.
3. Click **Generate**, then **Save** to export (`zaprootCA.pem`).

### 4.2 Installing the Certificate in the Browser

**Firefox:**
1. Open **about:preferences#privacy** in the address bar.
2. Scroll to **Certificates > View Certificates > Authorities**.
3. Click **Import**, select `zaprootCA.pem`, and check **Trust this CA to identify websites**.

**Chrome (Windows/Linux/MacOS):**
1. Open **chrome://settings/security**.
2. Navigate to **Manage Certificates > Authorities**.
3. Click **Import**, select `zaprootCA.pem`, and confirm.