## Zygote Process

Zygote is a core system process responsible for launching Android applications. It is started during system boot and acts as a template for all application processes.

#### Purpose and Behavior:

- Loads and pre-initializes core Java classes and resources (e.g., `android.*`, `java.*`).
    
- Maintains a warm Dalvik/ART VM state.
    
- When a new application is launched, Zygote forks a child process to execute the app, leveraging the copy-on-write model for efficiency.
    

#### Technical Characteristics:

- Communicates via a Unix domain socket (`/dev/socket/zygote`).
    
- Receives commands from the Activity Manager Service (AMS).
    
- The forked child process executes the application in a sandboxed environment.
    

#### Security Relevance:

- Isolation: Each app runs in its own UID and process space.
    
- Attack surface includes malformed fork requests or exploitation of native code within the Zygote context.
    

---

## Android Application States

Android applications go through different lifecycle states managed by the system:

1. **Running (Foreground)**
    
    - The activity is visible and has user focus.
        
    - Highest priority, unlikely to be killed.
        
2. **Paused**
    
    - Activity is partially visible (e.g., dialog in front).
        
    - Still resident in memory.
        
3. **Stopped**
    
    - Activity is not visible, but the process is alive.
        
    - May be killed by the system if memory is needed.
        
4. **Killed**
    
    - Process is terminated to reclaim memory.
        
    - App must be restarted from scratch.
        

Understanding state transitions is critical for detecting logic flaws or abuse of exported components in pentesting.

---

## Android Permissions

Permissions regulate access to system resources and sensitive APIs. They are declared in the `AndroidManifest.xml` and categorized as follows:

#### 1. Install-Time Permissions

- Granted at installation.
    
- Applies to Android versions < 6.0 (API < 23).
    

#### 2. Normal Permissions

- Access to non-sensitive features (e.g., Internet access).
    
- Automatically granted at install time.
    

#### 3. Runtime Permissions

- Required for sensitive actions (e.g., camera, location).
    
- Requested at runtime from Android 6.0+.
    

```java
if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
    ActivityCompat.requestPermissions(activity, new String[]{Manifest.permission.CAMERA}, 100);
}
```

#### 4. Signature Permissions

- Granted only to apps signed with the same certificate as the declaring app.
    
- Used for inter-app communication within trusted suites.
    

#### 5. Special Permissions

- Require user interaction in system settings.
    
- Example: `SYSTEM_ALERT_WINDOW`, `WRITE_SETTINGS`
    

---

## Network Security in Android

#### TLS by Default

- Since Android 9 (API 28), all HTTP traffic must use HTTPS.
    
- Plain HTTP is blocked unless explicitly allowed via `networkSecurityConfig`.
    

```xml
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">example.com</domain>
  </domain-config>
</network-security-config>
```

#### DNS over TLS

- Enabled by default in Android 9+.
    
- Provides encrypted DNS resolution to prevent interception.
    
- Uses port 853 and configurable via Private DNS settings.
    

---

## Anti-Exploitation Mechanisms

Android implements several exploit mitigation strategies to harden its runtime environment:

#### 1. ASLR (Address Space Layout Randomization)

- Randomizes memory layout (stack, heap, libraries) at runtime.
    
- Prevents reliable return-to-libc or ROP exploits.
    

#### 2. KASLR (Kernel ASLR)

- Randomizes kernel memory base address.
    
- Increases difficulty of kernel exploits.
    

#### 3. PIE (Position-Independent Executables)

- All native binaries are compiled as PIE.
    
- Required for ASLR to be effective.
    

#### 4. NX / DEP (No-eXecute / Data Execution Prevention)

- Prevents execution in memory marked as data.
    
- Stops classic buffer overflow shellcode execution.
    

#### 5. Stack Canaries

- Adds random values before return addresses on the stack.
    
- Detection of stack overflows before they can overwrite return pointers.
    
