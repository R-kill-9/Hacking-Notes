**pspy** is a lightweight tool for monitoring processes on Linux systems without requiring elevated privileges. It is commonly used in privilege escalation scenarios to identify processes running as other users or root.


---

## Downloading Pspy
Download the appropriate version of pspy from the [pspy GitHub repository](https://github.com/DominicBreuker/pspy).

```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
```

## Usage

#### Basic Execution

Run pspy to monitor all processes:

```bash
./pspy64
```

#### Filter by user
To focus on processes started by a specific user:

```bash
./pspy64 | pgrep <username>
```