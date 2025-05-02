**Android** penetration testing is the process of simulating attacks on Android applications and environments to identify and fix security vulnerabilities. It includes assessing the app code, data storage, communication methods, and overall behavior.

> These notes are based on content from [Hack The Box's blog on mobile penetration testing](https://www.hackthebox.com/blog/intro-to-mobile-pentesting#mcetoc_1fins0u9s4i4).
---

## Android Package (APK) File Structure

An APK is the file format used to install Android apps. It contains:

- **`AndroidManifest.xml`** – app permissions, components, version info.
- **`classes.dex`** – compiled app code.
- **`res/`** – resources like layout files and images.
- **`lib/`** – native libraries.
- **`META-INF/`** – metadata and signatures.


---

## OWASP Mobile Top 10 Vulnerabilities (Explained with Examples)

1. **Improper Platform Usage**  
    Misuse of Android components like Intents or permissions.  
    _Example_: Exported Activities accessed without proper checks.
    
2. **Insecure Data Storage**  
    Sensitive data stored in plaintext on device (e.g., SharedPreferences).  
    _Example_: Storing login credentials in an unencrypted SQLite DB.
    
3. **Insecure Communication**  
    Transmitting data over HTTP instead of HTTPS.  
    _Example_: Intercepting credentials using a proxy tool like Burp Suite.
    
4. **Insecure Authentication**  
    Weak or missing checks for user identity.  
    _Example_: Login bypass by manipulating the app state locally.
    
5. **Insufficient Cryptography**  
    Using outdated or broken encryption methods.  
    _Example_: Using ECB mode for AES encryption.
    
6. **Insecure Authorization**  
    Failing to enforce proper access control.  
    _Example_: Accessing admin functions as a normal user.
    
7. **Poor Code Quality**  
    Presence of bugs due to bad coding practices.  
    _Example_: Hardcoded API keys or credentials in the code.
    
8. **Code Tampering**  
    Modifying APKs to change behavior or bypass security.  
    _Example_: Removing license checks to use paid features for free.
    
9. **Reverse Engineering**  
    Extracting source code or logic from the APK.  
    _Example_: Using JADX to view and understand the code.
    
10. **Extraneous Functionality**  
    Hidden/debug functions left in production.  
    _Example_: Unused APIs or logs that expose internal app data.
    

---

## Suggested Tools for Android Penetration Testing

- **ADB** – Android Debug Bridge, used for interacting with the device.
- **JADX** – Reverse engineering and code analysis.
- **apktool** – Decompile/recompile APK files.
- **Burp Suite** – Intercept and modify app traffic.
- **MobSF** – Automated static and dynamic analysis.

---

## Android Penetration Testing Techniques 

#### Local Data Storage Enumeration

**Objective**: Identify sensitive information stored insecurely on the device.

Android applications often store data locally for performance or usability reasons. However, when sensitive data is stored without proper encryption or in accessible locations, it becomes a prime target for attackers.

**Steps**:

- Use **ADB (Android Debug Bridge)** to access the device’s file system:
```bash
adb shell
run-as com.example.app
cd /data/data/com.example.app/
```

- Explore the following directories:
    - `shared_prefs/` – stores XML files, often containing tokens, credentials, or app settings.
    - `databases/` – SQLite databases that may include user data, messages, or app logic.
    - `files/` and `cache/` – general-purpose storage that may contain logs, documents, or temp data.

**Example**: An attacker finds an `auth.xml` file in `shared_prefs/` that contains a plaintext access token. This token can be reused to impersonate a legitimate user.


#### Extracting APK Files

**Objective**: Obtain the application package for offline analysis.

Extracting the APK allows for reverse engineering, static code analysis, and decompilation. There are multiple ways to retrieve APK files:

**Methods**:

- **From the device using ADB**:
```bash
adb shell pm path com.example.app
adb pull /data/app/com.example.app-1/base.apk
```

- **Via third-party tools or apps**: Tools like APK Extractor or open-source scrapers can simplify APK retrieval.
- **From online repositories**: APKs can often be found on sites like APKMirror or extracted from Google Play using automated tools.

**Example**: After extracting the APK, the tester uses it for further decompilation and discovers hardcoded API keys inside.

#### Reverse Engineering Using JADX

**Objective**: Read and analyze the application’s source code to discover logic flaws and secrets.

JADX is a decompiler that converts the `classes.dex` (Dalvik Executable) file back into readable Java code. This is useful for understanding the internal logic of the app.

**Process**:

- Open the APK in **JADX GUI**.
    
- Navigate through packages and classes to look for:
    - Hardcoded credentials or secrets.
    - API endpoints and tokens.
    - Business logic and hidden features.
    - Logging/debug messages.

**Example**: A tester finds a class `DebugUtils.java` that contains a hidden debug flag allowing access to a developer menu with admin capabilities.


#### Decompiling and Recompiling the APK File

**Objective**: Modify application behavior by altering its resources or logic, then reinstall the modified app.

This technique is useful for bypassing client-side restrictions, modifying UI elements, or changing app flow.

**Steps with `apktool`**:

1. **Decompile** the APK:
```bash
adb shell pm path com.example.app
adb pull /data/app/com.example.app-1/base.apk
```
2. Modify `smali` code, resources, or manifest.

3. **Rebuild** the APK:
```bash
apktool b app_source -o modified.apk
```
4. **Sign** the APK using `jarsigner` or `apksigner`:
```bash
apksigner sign --key testkey.pk8 --cert testkey.x509.pem modified.apk
```

**Example**: A login check is enforced via client-side logic. The tester edits the `LoginActivity.smali` file to skip credential validation and always return a “success” state.

#### Intercepting Network Traffic

**Objective**: Inspect and manipulate data transmitted between the application and its backend servers.

Network communication is a critical aspect of mobile apps, and insecure implementation can lead to serious vulnerabilities such as information leakage, insecure authentication, or session hijacking.

**Process**:

- Set up a **proxy tool** like **Burp Suite** or **mitmproxy**.
- Configure the Android device to use the proxy.
- Install the proxy’s **CA certificate** on the device to inspect HTTPS traffic (may require root or a custom certificate store on newer Android versions).
- Use the proxy to monitor, replay, and tamper with requests and responses.

**Targets**:

- Check for **unencrypted communication** (e.g., HTTP instead of HTTPS).
- Look for sensitive data in headers, URLs, or bodies.
- Attempt **parameter tampering**, replay attacks, or session theft.

**Example**: An intercepted login request reveals that the username and password are sent in plaintext. The tester modifies the username field to escalate privileges and accesses admin functionality.