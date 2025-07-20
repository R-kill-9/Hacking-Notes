**QARK** (Quick Android Review Kit) is an open-source tool developed for static security analysis of Android applications.

## Features

- Identifies issues such as:
  - Exported components without permission protection
  - Insecure use of WebView
  - Hardcoded credentials or secrets
  - Use of deprecated or insecure APIs
  - Debuggable applications
  - Weak cryptographic implementations
  - Misconfigured `AndroidManifest.xml`

- Can generate:
  - Human-readable HTML reports
  - Exploit POC APKs for certain vulnerabilities (e.g., exported activities)


## Installation

QARK is written in Python and runs in CLI. It works best in Linux environments or via Docker.

#### Install via Docker (Recommended)

```bash
git clone https://github.com/linkedin/qark
cd qark/docker
./run_qark_docker.sh
```

## Usage

You can analyze either:

- Source code (Java)    
- APK file (recommended if source is not available)

**Example (analyzing APK):**
```bash
python qarkMain.py --source 2 --apk /path/to/app.apk
```

**Example (analyzing Java source):**

```bash
python qarkMain.py --source 1 --path /path/to/java/code
```

## Output

- Generates an interactive report with:
    - List of vulnerabilities
    - Risk levels
    - Code locations (if source provided)
- Offers option to build a proof-of-concept APK for certain vulnerabilities (like exported activities).


## Typical Vulnerabilities Detected
|Type|Example|
|---|---|
|Exported Activity|Activity exposed without permission in manifest|
|WebView Misuse|JavaScript enabled + no validation|
|Insecure Logging|Logging sensitive data (tokens, passwords)|
|Hardcoded Data|API keys, credentials in source code|
|Weak Crypto|Use of ECB mode, no salt, weak key sizes|
|Insecure Permissions|Over-permissive manifest entries|
|Debuggable App|`android:debuggable="true"` in release APK|