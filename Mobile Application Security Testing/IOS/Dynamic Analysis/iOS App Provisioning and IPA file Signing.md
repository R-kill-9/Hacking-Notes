## Developer Account (Apple ID Provisioning)

- Since **Xcode 7**, you can deploy apps to your iOS device using only a **free Apple ID** — no paid developer account is required.
    
- **Free provisioning**:
    
    - Apps signed with a free Apple ID expire after **7 days**.
        
    - Limited entitlements (no push notifications, in-app purchases, or Game Center).
        
- **Paid Apple Developer Program ($99/year)**:
    
    - Apps remain valid for **1 year**.
        
    - Full set of entitlements available (in-app purchases, Game Center, push notifications).
        
    - More stable for jailbreak tools or apps you want to keep installed.
        

---

## Apple Configurator & Developer Mode (iOS 16+)

- **Developer Mode** must be enabled on iOS 16 and later for sideloaded apps to run.
    
- To trigger the Developer Mode prompt:
    
    1. Connect the device to **Apple Configurator 2** (macOS) or Xcode.
        
    2. Install or run any test IPA.
        
    3. The iPhone will display a **Developer Mode prompt**.
        
    4. Go to: **Settings → Privacy & Security → Developer Mode** → toggle ON → reboot → confirm.
        

Without Developer Mode, sideloaded apps will crash or refuse to open.

---

## Signing IPA Files

- **All sideloaded apps (including jailbreak loaders)** must be signed before they can run.
    
- Options:
    
    - **Free Apple ID** → 7-day limit, requires weekly reinstallation.
        
    - **Paid developer certificate** → 1-year validity, avoids repeated “trust” steps.
        
    - **.p12 certificate + provisioning profile** → convenient if exporting certs from a dev account; same 1-year validity.
        
- Signing ensures the app passes iOS security checks and can be trusted from **Settings → General → VPN & Device Management**.
    

---

## Sideloading with Sideloadly 

Sideloadly is a popular cross-platform tool to install `.ipa` files on iOS by handling signing + installation.

### Steps:

1. Install **Sideloadly** on Windows or macOS.
    
    - Windows: also install **iTunes desktop version** (for device drivers).
        
2. Connect iPhone via USB, unlock it, and tap **Trust this computer**.
    
3. Open Sideloadly and drag the `.ipa` file into the window.
    
4. Choose signing method:
    
    - Enter Apple ID (free or paid).
        
    - Or load `.p12` + provisioning profile.
        
5. Click **Start**.
    
6. On iPhone: **Settings → General → VPN & Device Management** → trust the developer profile if required.
    
7. Launch the app.
    

**Notes:**

- Free Apple ID apps expire after 7 days (must be re-sideloaded).
    
- Paid account / `.p12` signed apps last 1 year.
    
- iOS 16+ requires **Developer Mode** enabled.