---

## iOS Application Extraction Using Filza, WebDAV and Kali Linux

In jailbroken iOS environments, a practical method for extracting installed applications relies on combining Filza file manager with its built-in WebDAV server. This approach avoids SSH limitations and provides direct filesystem access from a remote machine such as Kali Linux.

Filza is installed through package managers like Sileo on jailbroken devices. Once installed, it allows browsing the full filesystem, including restricted application directories such as `/var/containers/Bundle/Application/`, where iOS stores installed app bundles.

---

## Application Location in Jailbroken iOS Filesystem

iOS does not store applications as single files. Instead, each app is placed inside a UUID-based directory structure. The actual executable bundle is located inside a `.app` directory, which is the only relevant component for reverse engineering or IPA reconstruction.

Typical path structure:

```text
/var/containers/Bundle/Application/<UUID>/AppName.app
```

Inside this directory are the binary, `Info.plist`, frameworks, and signature files required for execution and analysis.

---

## Using Filza to Prepare Application Dumps

Once inside Filza, the analyst navigates to the application bundle directory and compresses the `.app` folder directly into a ZIP archive. This step ensures that the full structure is preserved before transfer.

The process is typically:

- Navigate to `/var/containers/Bundle/Application/`
    
- Locate the correct UUID folder
    
- Enter the `.app` directory
    
- Create a ZIP archive using Filza’s built-in compression feature
    

This produces a portable archive that can be transferred outside the device.

---

## Enabling WebDAV for Remote Access

Filza includes a WebDAV server that can be enabled directly from its settings. Once activated, the iOS device exposes its filesystem over the local network using an HTTP-based endpoint.

This allows remote tools on Kali Linux to interact with the device without requiring SSH or USB forwarding. The WebDAV service essentially mirrors the filesystem, including the compressed ZIP file created earlier.

---

## Retrieving Files from Kali Linux Using wget

From the Kali machine, the exposed WebDAV endpoint can be accessed using standard HTTP tools such as `wget`. This enables automated or recursive downloading of extracted application bundles.

Example command:

```bash
wget -r --no-parent http://<iphone-ip>:<port>/var/containers/Bundle/Application/<UUID>/
```

This retrieves the ZIP file containing the `.app` bundle to the local analysis environment.

---

## Reconstructing the IPA from Extracted Data

Once the ZIP file is transferred to Kali, it must be converted into a valid IPA structure. iOS requires a strict hierarchy where the application bundle is placed inside a `Payload` directory.

```bash
unzip app.zip
mkdir Payload
mv AppName.app Payload/
zip -r app.ipa Payload
```

The resulting IPA now follows the expected format for tools like MobSF and can be used for static analysis or reverse engineering.
