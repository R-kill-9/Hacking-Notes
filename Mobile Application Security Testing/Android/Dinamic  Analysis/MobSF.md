**MobSF** provides both **static** and **dynamic** analysis capabilities for Android apps. Below is a breakdown of the technical steps and features.

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