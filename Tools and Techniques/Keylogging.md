**Keylogging** is a post-exploitation technique used to capture keystrokes from a compromised system. This information is often used to steal credentials, sensitive data, or monitor user activity.

## Implementing Keylogging in Metasploit

Metasploit's Meterpreter includes a keylogging feature.

##### Steps:

1. **Setup a Meterpreter Session**:

Compromise the target and gain a Meterpreter session.

2. **Start Keylogging**:

```bash
meterpreter > keyscan_start
```
This starts capturing keystrokes from the target system.

3. **Dump Captured Keystrokes**:

```bash
meterpreter > keyscan_dump
```
4. **Stop Keylogging**:
```bash
meterpreter > keyscan_stop
```
