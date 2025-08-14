## Overview

The iPhone 7 uses the **A10 chip**, which is vulnerable to the **checkm8** bootrom exploit.  
This makes it possible to jailbreak any firmware version on the device, including iOS 15.8.3, using **palera1n**.  
The jailbreak will be **semi-tethered**.

> [Useful Tutorial](https://www.youtube.com/watch?v=3Vd-lbaH1MM)
---

## Requirements

- A computer running **Linux** or **macOS** (Windows requires a VM or WSL with USB passthrough).
- Original or high-quality USB cable.
- **palera1n** jailbreak tool.
- Full device backup (jailbreaking always carries risk).

---

## Jailbreaking process

#### 1. Install palera1n

Open a terminal on Linux/macOS and run:
```bash
sudo /bin/sh -c "$(curl -fsSL https://static.palera.in/scripts/install.sh)"
```


## 2. Enter DFU Mode

1. Power off the iPhone.
2. Hold **Power** for 3 seconds.
3. Without releasing Power, hold **Power + Volume Down** for 10 seconds.
4. Release Power but keep holding **Volume Down** for 5 more seconds.
5. Screen stays black → DFU mode is active.

#### 3. Run the Jailbreak

In the terminal:
```bash
palera1n --tweaks
```

- `--tweaks`: installs Sileo (package manager for installing tweaks/tools).
- If you want rootfs access only (no tweaks):
```bash
palera1n --semi-tethered
```

#### 4. First Boot

- Once the process finishes, the device will boot and show the **Sileo** app.
- Use Sileo to install tools such as:
    - **Frida** (for runtime instrumentation)
    - **OpenSSH** (for remote shell access)
    - **Objection** (for mobile app security testing)

---

## Important Notes

- **Semi-tethered**: if you reboot the device without running palera1n, it will boot into a non-jailbroken state until you re-run the jailbreak.
- iOS 15.8.3 is supported because **checkm8** is a hardware-level exploit that cannot be patched by Apple on A10 devices.
- Avoid updating to iOS 16.x unless you verify that palera1n supports your version.