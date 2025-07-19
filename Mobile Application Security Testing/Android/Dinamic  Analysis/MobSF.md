**MobSF** provides both **static** and **dynamic** analysis capabilities for Android apps. Below is a breakdown of the technical steps and features.


## Static Analysis with MobSF

1. **Preparing the APK**
    - Ensure the APK is not obfuscated or heavily packed for better results.
    - No need for source code. MobSF decompiles the APK internally.
    
2. **Uploading the APK**
    - Open MobSF in the browser: `http://127.0.0.1:8000`
    - Drag and drop the APK file into the interface or use the upload button.
3. **Analysis Process**
    - MobSF decompiles the APK using `apktool`, `dex2jar`, and `jadx`.
    - It extracts:
        - Manifest file (AndroidManifest.xml)
        - Code structure (Java source code approximation)
        - Certificates and permissions
        - API endpoints and URLs
        - Activities, services, broadcast receivers, content providers

4. **Static Analysis Output**
    - Code analysis with vulnerability detection (e.g., insecure WebView usage, exported components)
    - Hardcoded secrets, API keys, and credentials
    - Binary analysis (native libraries, certificate info)
    - Network and URL endpoints
    - Deep links and intent filters

---

## Dynamic Analysis with MobSF

Dynamic analysis simulates real device behavior to monitor app behavior at runtime.

1. **Start MobSF Dynamic Analyzer**
    - Click on "Dynamic Analyzer" in the MobSF interface.
    - MobSF launches a preconfigured Android emulator (or can connect to a real device if `adb` is configured properly).

2. **Device Connection**
    - Ensure the emulator or device is connected and visible via `adb devices`.
    - MobSF uses `Frida`, `mitmproxy`, and `adb` for dynamic instrumentation.
3. **Install and Monitor the App**
    - MobSF installs the APK on the emulator.
    - Network traffic is proxied through `mitmproxy`.
    - MobSF captures runtime logs, API calls, and behavior patterns.

4. **Features of Dynamic Analysis**
    
    - Runtime permission analysis
    - Traffic interception (HTTP/HTTPS)
    - Java method hooking using Frida (requires configuration)
    - API behavior analysis and data leakage detection
    - SSL pinning detection and bypass (if configured)


---

### API Usage (Optional Automation)

MobSF provides a REST API for automated testing pipelines.

- Get API key from MobSF settings
- Use the `/api/v1/upload` and `/api/v1/report_json` endpoints to automate scanning and retrieve results
- Example with `curl`:
```bash
curl -F "file=@app.apk" -H "Authorization: <your_api_key>" http://localhost:8000/api/v1/upload
```