**Androguard** is a Python-based open-source tool for static analysis and reverse engineering of Android applications.
It analyzes APK files and extracts detailed information about their structure, code, and resources without executing the app.


---

## Key Features

- **APK parsing:** Extract manifest, resources, certificates, and metadata.
- **DEX analysis:** Disassemble Dalvik bytecode (DEX files) into readable code.
- **Control Flow Graph (CFG):** Generate CFGs to visualize app behavior.
- **Call Graph generation:** Helps understand function calls and app flow.
- **Decompilation:** Converts DEX code back to pseudo-Java for easier reading.
- **Signature verification:** Check app signing certificates.
- **Search & Queries:** Search classes, methods, strings, or API usage inside the APK.
- **Supports obfuscated code:** Works even if apps use code obfuscation techniques.


---

## Basic Usage Examples

**Analyze an APK file**
After running:
```bash
androguard analyze <path_to_apk>
```
You enter the interactive shell with the APK loaded as `a`, DEX files as `d`, and analysis as `dx`.

You’ll see variables:

- `a` — APK object
- `d` — list of DalvikVMFormat (DEX) objects
- `dx` — Analysis object with cross references

**Extract app permissions**
```python
a.get_permissions()
```

**Selecting the Main DEX Object**
Since `d` is a list of DEX objects (usually one for simple apps), select the first for easier access:
```python
d = d[0]
```

**Listing All Classes**
Print the fully qualified class names inside the DEX:

```python
for cls in d.get_classes():
    print(cls.get_name())
```

**Searching for Specific Methods**
Find methods whose name contains "login" (example):
```python
for method in d.get_methods():
    if 'login' in method.get_name():
        print(method.get_class_name(), method.get_name())
```

**Extracting All Strings in the APK**
Analyze strings referenced by the app:
```python
for string in dx.get_strings():
    print(string)
```



## Graph Creation
Besides code inspection, **Androguard** can generate a **Call Graph** from an APK to understand how functions and methods interact with each other.

**Generate a Call Graph from the terminal**
```bash
androguard cg example.apk
```
This command creates a file in **.gml** (Graph Modeling Language) format containing the graph structure.

#### Viewing the Graph with Gephi

**Windows / macOS**:  
    Download the installer from the official website:  
    https://gephi.org

**Linux (Debian/Ubuntu)**:
Install Java (Gephi requires Java 17+):
```bash
sudo apt update
sudo apt install openjdk-17-jdk
```
Download the latest Gephi release (`.tar.gz`) from:  
    https://gephi.org/users/download/

Extract the archive:
```bash
tar -xvzf gephi-*.tar.gz
```

Run Gephi:
```bash
cd gephi-*
./bin/gephi
```