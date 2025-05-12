## Internal Storage

User-installed apps are stored in `/data/app`, while system applications reside in `/system/app` or `/system/priv-app`.  
Each application also has a private directory at `/data/data/<package_name>/`, which is sandboxed and only accessible by that app's UID. Sensitive data should ideally be stored here.

---

## External Storage

External storage refers to the shared area accessible by all applications. It is typically mounted at `/sdcard` or `/mnt/sdcard`. On devices without physical SD cards, the system emulates external storage in internal memory.  
To write to external storage, an app must declare the `WRITE_EXTERNAL_STORAGE` permission in the manifest.  
External storage is not secure by default, as any app with the correct permissions can read/write from it. Sensitive information should not be stored here.

---

## MDM (Mobile Device Management)

MDM refers to systems used by organizations to control and manage mobile devices remotely.  
Features include:

- Enforcing security policies (e.g., passcode requirements, encryption)
    
- Installing or removing apps remotely
    
- Locking or wiping a device in case of loss or theft
    
- Monitoring device compliance  
    MDMs operate using APIs provided by Android Enterprise and often integrate with Google Play’s managed services.
    

---

## Device Tracking

Device tracking allows the location and activity of a mobile device to be monitored.  
Tracking can be performed through:

- GPS/location services
    
- Wi-Fi/cell tower triangulation
    
- MDM integration for enterprise environments  
    Tracking features can be found in services like Google's Find My Device or in corporate management tools.  
    Security and privacy concerns arise when tracking is done without user consent or by malicious apps.
    

