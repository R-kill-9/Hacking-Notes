**Sandboxing** in Android is a fundamental security mechanism that isolates applications from one another and from the operating system. This isolation ensures that one app cannot access the data or resources of another app unless explicitly allowed.

## UID-Based Isolation
When an Android app is installed, the system assigns it a unique **Linux user ID (UID)**. This UID is used to enforce file and process separation at the operating system level.  

Example: 

- App A: UID 10087     
- App B: UID 10088  

Even if both apps run under the same user account (the phone user), they run as different system users.

#### Shared UIDs 
Android allows multiple applications to share the **same UID** if they are signed with the **same certificate** and explicitly declare a `sharedUserId` in their `AndroidManifest.xml` file.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:sharedUserId="com.example.shared" >
```

This configuration disables the default sandboxing between those apps, allowing them to:

- Access each other's private data stored in `/data/data/`
- Run in the same Linux process (optional, depending on process management)
- Share the same permission set, including dangerous or custom permissions

**Example:**

If App A requests this:
```xml
<uses-permission android:name="android.permission.CAMERA" />
```

Then the system grants the CAMERA permission to the **shared UID**.

So even if App B doesn't request CAMERA in its manifest, it can still do this:
```xml
Camera cam = Camera.open(); // Works because UID has permission
```


## Filesystem Isolation
Each app gets its own directory in `/data/data/<package_name>/`. By default, only that app (with its assigned UID) has permission to read/write within this directory.

Example command (from a rooted shell):
```bash
ls -la /data/data
```
You will see each app has its own directory with permissions like:
```kotlin
drwxr-x--x  5 u0_a87  u0_a87  4096 /data/data/com.example.app
```
Trying to `cd` into another app's directory with a different UID (without root) will result in a permission denied error.

## Process Isolation  
Each app runs in its own Linux process. These processes are completely separated unless the developer uses specific mechanisms to share data (e.g., content providers or AIDL).

If you try to `su` into another UID directly:
```kotlin
su 10088
```
You’ll get an interactive shell as that app’s user (if allowed), but you won’t be able to access other apps' files without proper privileges or exploitation.

