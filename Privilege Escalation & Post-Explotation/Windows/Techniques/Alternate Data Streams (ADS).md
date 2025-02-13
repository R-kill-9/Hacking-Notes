**Alternate Data Streams** (ADS) are a feature of the NTFS file system in Windows that allow a file to store multiple streams of data. In addition to the primary or visible stream, extra streams can be attached to a file without affecting its main content or size as displayed in the file explorer.

## How ADS Work

Each file on an NTFS partition has a default data stream (e.g., the visible content of a text file). ADS allows hidden streams to be added in this format:

```bash
filename:streamname
```

The `filename` is the primary file, while `streamname` is the hidden stream.

This technique can be used to hidden malicious or special payloads in the metadata of a legit file and being able to execute it.

### Example using WinPEAS
1. **Obtain the WinPEAS Executable**: Download the `winPEAS.exe` file to a working directory.  
2. **Embed WinPEAS into ADS**: Use the `type` command in the Windows Command Prompt to attach the WinPEAS executable as a hidden stream to a file. 

```bash
type winPEAS.exe > benign.txt:hidden
```

- `benign.txt` is a harmless-looking file, like a text file or document.
- `hidden` is the name of the ADS.
3.  **Execute WinPEAS from ADS**: To execute WinPEAS directly from the hidden stream:
```bash
start .\benign.txt:hidden
```