**Ghidra** is a free and open-source software reverse engineering (SRE) framework developed by the NSA. It provides a suite of tools for analyzing compiled code on a variety of platforms, supporting disassembly, decompilation, debugging, and scripting.

## Installation

#### Requirements

- Java Runtime Environment (JRE) 11 or higher (Ghidra bundles OpenJDK 11 from version 10.0)
- Minimum 4GB RAM recommended
```bash
sudo apt install ghidra
```

## Basic Usage

#### Import binary

- File > Import File
- Select executable (PE, ELF, Mach-O, etc.)
- Select language/architecture
- Run initial analysis

#### Analysis options

- Configure analyzers (functions, strings, etc.)
- Can rerun analysis later via Analyze > Auto Analyze

---

## Key Features

- **Disassembler:** Converts binary code to assembly.
- **Decompiler:** Converts assembly to high-level pseudocode (C-like).
- **Scripting:** Automate with Java or Python (Jython).
- **Cross-references:** Track where functions/data are used.
- **Patch binaries:** Modify instructions directly in Ghidra.