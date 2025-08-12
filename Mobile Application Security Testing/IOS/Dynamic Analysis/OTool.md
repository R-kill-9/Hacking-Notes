**OTool** is a macOS command-line utility for inspecting the contents of Mach-O binaries (the executable format used in macOS and iOS apps).  
It’s especially useful for reverse engineering and checking linked libraries.

---

### Basic Usage 

**Identify the file type**
```bash
file DVIA-v2
```

Shows the architecture and binary format of the file.

**View Mach-O header**
```bash
otool -h DVIA-v2
```

Displays the header information, including CPU type, number of load commands, and other binary metadata.

**List linked libraries**
```bash
otool -l DVIA-v2 | grep -A 5 LC_LOAD_DYLIB | grep name
```

This extracts the names of dynamically linked libraries.
