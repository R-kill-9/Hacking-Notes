**Penelope** is a Python‑based shell handler designed as a modern replacement for netcat. Below are technical notes in English with practical commands to help you understand and use it effectively [github.com](https://github.com/brightio/penelope).

![](Penelope.png)

---

## Installation

- **Direct download and run:**

```bash
wget https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py
python3 penelope.py
```

- **Install via pipx (recommended for isolation):**

```bash
pipx install git+https://github.com/brightio/penelope
```


---

## Usage

- **Listen for reverse shells:**

```bash
penelope                # Listen on 0.0.0.0:4444
penelope -p 5555        # Listen on port 5555
penelope -i eth0 -p 5555 # Listen on eth0:5555
```

- **Show reverse shell payloads:**

```bash
penelope -a
```

- **Connect to a bind shell:**

```bash
penelope -c target -p 3333
```

- **SSH reverse shell integration:**

```bash
penelope ssh user@target
penelope -p 5555 ssh user@target
penelope -i eth0 -p 5555 -- ssh -l user -p 2222 target
```

- **Serve files via HTTP:**

```bash
penelope -s /path/to/file_or_folder
```


#### Command Line Options 

- `-p PORT` → set port for listening/connecting.
- `-i INTERFACE` → specify interface/IP.
- `-c HOST` → connect to bind shell.
- `-s FILE/FOLDER` → serve via HTTP.
- `-m NUM` → maintain NUM shells per target.
- `-U` → disable shell upgrade.
- `-d` → debug mode.
