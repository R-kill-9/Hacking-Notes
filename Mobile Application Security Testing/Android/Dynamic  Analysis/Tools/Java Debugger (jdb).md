
`jdb` is a command-line tool used to debug Java programs. In Android, it can be used to attach to running applications—provided they are debuggable—and inspect their execution at runtime.

---

## Prerequisites

Before using `jdb` in Android, the following conditions must be met:

- The target app must be compiled with `android:debuggable="true"` in the manifest.
- The Android device or emulator must be connected and accessible via `adb`.
- Android SDK (including `jdb`) must be installed and accessible in your system.
- The app should be running on the device.

---

## 1. Identifying the Target Process

Use `adb` to find the PID of the target application.

```bash
adb shell ps | grep <package_name>
```

**Example:**

```bash
adb shell ps | grep com.example.vulnerableapp
```

You will get output like:

```bash
u0_a123   12345  ... com.example.vulnerableapp
```



## 2. Port Forwarding to JDWP

Use `adb` to forward a local TCP port to the JDWP port on the device for the selected PID.

```bash
adb forward tcp:8700 jdwp:<PID>
```

**Example:**

```bash
adb forward tcp:8700 jdwp:12345
```


## 3. Attaching jdb to the Process

Now attach to the forwarded JDWP port using `jdb`.

```bash
jdb -attach localhost:8700
```

This will open an interactive debugging session.


---

## Useful jdb Commands

| Command                    | Description                                                                                     |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| `classes`                  | Lists all currently loaded classes in the JVM.                                                  |
| `stop in <class>.<method>` | Sets a breakpoint in the specified method. Example: `stop in com.example.MainActivity.onCreate` |
| `stop at <class>:<line>`   | Sets a breakpoint at a specific line in a class. Example: `stop at com.example.MainActivity:42` |
| `cont`                     | Resumes the program execution after a breakpoint.                                               |
| `run`                      | Starts execution of the main class. Only works if the app was launched via `jdb`.               |
| `locals`                   | Lists all local variables in the current stack frame.                                           |
| `print <var>`              | Displays the value of the specified variable.                                                   |
| `set <var> = <value>`      | Sets the value of a variable during debugging.                                                  |
| `threads`                  | Lists all active threads in the application.                                                    |
| `thread <id>`              | Switches to a specific thread by ID.                                                            |
| `where`                    | Displays the current call stack (stack trace) of the current thread.                            |
| `where all`                | Displays the call stacks of all threads.                                                        |
| `next`                     | Executes the next line in the current thread, stepping over method calls.                       |
| `step`                     | Steps into the method being called on the current line.                                         |
| `clear`                    | Clears all breakpoints.                                                                         |
| `exit` or `quit`           | Exits the `jdb` session.                                                                        |