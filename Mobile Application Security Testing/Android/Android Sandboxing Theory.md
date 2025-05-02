**Sandboxing** in Android is a fundamental security mechanism that isolates applications from one another and from the operating system. This isolation ensures that one app cannot access the data or resources of another app unless explicitly allowed.

## UID-Based Isolation
When an Android app is installed, the system assigns it a unique **Linux user ID (UID)**. This UID is used to enforce file and process separation at the operating system level.  

Example: 

- App A: UID 10087     
- App B: UID 10088  

Even if both apps run under the same user account (the phone user), they run as different system users.

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