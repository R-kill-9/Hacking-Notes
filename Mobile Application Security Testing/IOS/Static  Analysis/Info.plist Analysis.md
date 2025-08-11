The `Info.plist` file in an iOS app declares metadata and system behaviors that may impact **security**, **privacy**, and **execution** flow. Misconfigured or overly permissive flags may lead to **data leakage**, **unexpected behavior**, or **attack surface exposure**.


---


## Debugging & Security Flags
| Setting                                    | Risk                                                                                                 |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `UIFileSharingEnabled`                     | Allows file system access over USB (e.g., via iTunes); can expose internal files if not restricted.  |
| `LSSupportsOpeningDocumentsInPlace`        | Allows apps to directly edit shared documents. Can leak data if combined with external apps.         |
| `UIApplicationExitsOnSuspend`              | App fully quits when backgrounded; affects persistence but may be abused to hide execution flow.     |
| `UIBackgroundModes`                        | Enables background tasks (e.g., audio, location). Expands attack surface and persistence mechanisms. |
| `ITSAppUsesNonExemptEncryption`            | Declares whether the app uses encryption. Misuse can impact compliance and security review.          |
| `UIApplicationSupportsIndirectInputEvents` | Enables alternative input methods. May affect accessibility, automation or testing behaviors.        |
```xml
<key>UIFileSharingEnabled</key>
<true/>
<key>LSSupportsOpeningDocumentsInPlace</key>
<true/>
<key>UIBackgroundModes</key>
<array>
    <string>audio</string>
    <string>location</string>
</array>
```


---

## Network & Data Security Risks
| Setting                      | Risk                                                                                                           |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `NSAllowsArbitraryLoads`     | Disables App Transport Security (ATS); allows HTTP traffic. Can enable MITM attacks.                           |
| `NSExceptionDomains`         | Specifies domains where ATS is relaxed (e.g., allows HTTP or invalid certs). Weakens transport layer security. |
| `NSAllowsLocalNetworking`    | Allows unencrypted access to local network. May leak sensitive info via mDNS or broadcast protocols.           |
| `NSAppTransportSecurity`     | Global ATS enforcement setting. Should require HTTPS and strong TLS.                                           |
| `NSContactsUsageDescription` | Required to access Contacts. Must be present or app will crash if API is used.                                 |
```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>insecure.example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key>
            <true/>
        </dict>
    </dict>
</dict>
```


---

## Privacy & Data Exposure
| Setting                            | Risk                                                                                                  |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `NSCameraUsageDescription`         | Required for camera access. Missing or unclear descriptions may cause user denial or abuse suspicion. |
| `NSMicrophoneUsageDescription`     | Required for microphone access. Overuse may raise surveillance concerns.                              |
| `NSPhotoLibraryUsageDescription`   | Grants read access to photo library. Can leak personal images if misused.                             |
| `NSLocationAlwaysUsageDescription` | Enables always-on location tracking. High privacy impact.                                             |
| `NSUserTrackingUsageDescription`   | Indicates use of tracking (e.g., for ads). Required by App Store for IDFA access.                     |
```xml
<key>NSCameraUsageDescription</key>
<string>This app needs camera access to scan QR codes.</string>
<key>NSLocationAlwaysUsageDescription</key>
<string>Used for continuous location tracking.</string>
```


---

## App Execution & IPC Risks
|Setting|Risk|
|---|---|
|`CFBundleURLTypes`|Registers custom URL schemes. May allow unauthorized IPC or deep link hijacking.|
|`CFBundleExecutable`|Declares the name of the app binary. Useful for reverse engineering and mapping Mach-O.|
|`CFBundleIdentifier`|Unique app ID. Used in provisioning, entitlements, and app resolution.|
|`UIRequiresFullScreen`|Prevents Split View (multitasking). Not directly a security risk, but alters execution context.|
|`LSApplicationQueriesSchemes`|Allows querying installed URL schemes. Can be abused for app fingerprinting or indirect IPC discovery.|
```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLName</key>
        <string>com.example.myapp</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>

<key>LSApplicationQueriesSchemes</key>
<array>
    <string>whatsapp</string>
    <string>fb</string>
</array>
```