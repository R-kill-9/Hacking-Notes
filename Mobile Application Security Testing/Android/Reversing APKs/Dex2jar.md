**dex2jar** is a tool used to convert Android `.dex` (Dalvik Executable) files into `.class` files (Java bytecode), allowing further analysis using Java decompilers. It is commonly used in reverse engineering workflows to recover readable Java code from APKs.

## Installation
dex2jar is distributed as a precompiled ZIP package. It does not require compilation or installation.

1. Download the latest version from the official GitHub repository:  
   [https://github.com/pxb1988/dex2jar](https://github.com/pxb1988/dex2jar)
2. Extract the ZIP file.

3. On Linux/macOS, make the scripts executable:

```bash
chmod +x d2j-dex2jar.sh
```

## 1. Extract classes.dex from APK

Before using `dex2jar`, you need to extract the `.dex` file from the APK:

```bash
unzip app.apk classes.dex
```

## 2. Convert DEX to JAR

Use `dex2jar` to convert the `.dex` file into a `.jar`:
```bash
d2j-dex2jar.sh classes.dex -o output.jar
```

## 3. View Decompiled Code

Open the resulting `.jar` file with a Java decompiler to explore the source code:

- **JD-GUI** – GUI-based decompiler
- **CFR** – Command-line Java decompiler
- **Fernflower** – IntelliJ's internal decompiler
```bash
java -jar cfr.jar output.jar --outputdir decompiled_source
```
