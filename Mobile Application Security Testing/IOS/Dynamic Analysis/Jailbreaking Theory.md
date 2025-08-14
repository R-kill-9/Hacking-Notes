**Jailbreaking** is the process of gaining elevated privileges on iOS devices by exploiting kernel or system protections. It allows arbitrary code execution, often via spawning an SSH shell, and modifies system behavior to bypass Apple’s restrictions [The Apple Wiki](https://theapplewiki.com/wiki/Jailbreak?utm_source=chatgpt.com).



---


## Purpose and Capabilities:

- Grants **root access** to the device and access to protected system areas.
- Enables installation of unsigned apps, tweaks, and modifications not allowed by Apple.
- Often installs a package manager like Cydia to manage third-party repositories.
- Overcomes many OS-level constraints (locked bootloader, AMFI, KPP, etc.).


---


## Jailbreak Types 

|Type|Persistence|Computer Required After Reboot?|Notes|
|---|---|---|---|
|**Tethered**|None|Yes|Rare today; requires a host device on every boot.|
|**Semi-tethered**|None|Yes (to re-enable jailbreak)|Boots into stock iOS if not re-jailbroken. Example: **palera1n**.|
|**Untethered**|Permanent|No|Rare due to complexity and Apple’s improved security.|
|**Semi-untethered**|Persists until reboot|No (for normal usage), but requires re-run of jailbreak app|Example: Odyssey, unc0ver (when supported).|


---


## Exploit Categories

- **Bootrom Exploits** (e.g., **checkm8**):
    
    - Reside in the device's immutable ROM (cannot be patched by firmware updates).
        
    - Exploitation occurs before the OS is loaded.
        
    - Grants control over the boot chain, allowing downgrades, custom kernels, and bypass of signature checks.
        
    - Affects devices with A5–A11 SoCs.
        
- **iBoot Exploits**:
    
    - Occur during the iOS bootloader stage.
        
    - Can allow unsigned firmware loading but are patchable via software updates.
        
- **Kernel Exploits**:
    
    - Target vulnerabilities in the XNU kernel after the OS is loaded.
        
    - Often used for modern semi-untethered jailbreaks.
        
    - Requires bypassing mitigations like PAC (Pointer Authentication Codes) on newer chips.


---


## Tools & Frameworks per Exploit Type

#### Bootrom Exploits (e.g., **checkm8**)

- **Best for**: Permanent low-level access on compatible devices (A5–A11). Ideal for older devices or scenarios where firmware version doesn’t matter.
    
- **Common tools**:
    
- **[ipwndfu](https://github.com/axi0mX/ipwndfu)** → Python tool for checkm8 exploitation, entering pwned DFU mode.
```bash
./ipwndfu -p
```

- **[palera1n](https://github.com/palera1n/palera1n)** → Semi-tethered jailbreak for A9–A11 devices running iOS 15–16.x.
```bash
./palera1n.sh --tweaks
```

- **checkra1n** → GUI/CLI jailbreak for iOS 12–14.x (still usable on older firmwares).
- **futurerestore** → For downgrading/upgrading with saved SHSH blobs when in pwned DFU.
- **Usage case**: Security research on legacy hardware, persistent access for forensic analysis, bypassing activation lock in lab setups.


---

#### iBoot Exploits

- **Best for**: Temporarily loading unsigned iOS builds or custom recovery environments.
    
- **Common tools**:
    
    - **iBoot32Patcher** → Modifies iBoot images for custom firmware loading.
        
    - **kloader** → Loads custom kernels into memory via iBoot.
        
    - **img4tool** → Manipulates IMG4 firmware files.
        
- **Usage case**: Custom restore workflows, testing unsigned firmware builds, fuzzing early boot processes.
    

---

#### Kernel Exploits

- **Best for**: Modern devices and firmwares where bootrom exploits are unavailable.
    
- **Common tools**:
    
    - **unc0ver** → Semi-untethered jailbreak for iOS 11–14.x.
        
    - **Taurine** → Semi-untethered jailbreak for iOS 14.x with modern tweak injection.
        
    - **Odyssey** → Semi-untethered jailbreak for iOS 13.x.
        
    - **Frida** + **Frida Gadget** → Runtime hooking and instrumentation.
        
    - **Objection** → Security testing framework using Frida for dynamic analysis.
        
- **Usage case**: App security testing, runtime patching, reverse engineering without full filesystem modifications.