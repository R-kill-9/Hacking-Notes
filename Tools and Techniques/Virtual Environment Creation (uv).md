[`uv`](https://github.com/astral-sh/uv) is a fast Python package manager and virtual environment tool designed as a modern alternative to `pip` + `virtualenv`. One of its standout features is `uv run`, which allows you to run Python tools in isolated environments **without manual setup**.

## Installation

Install `uv` with a one-liner:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

This will place the binary in `~/.cargo/bin/uv` by default. Make sure it's in your `PATH`.

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```


---

## Usage: One-Off Virtual Environment

Instead of creating a virtual environment manually, you can execute a tool **in an isolated env directly**:

```bash
uv run <executable> [args]
```

For example, to run `bloodhound-python` without installing it globally:

```bash
uv run bloodhound-python -c All -u user -p pass -d domain.local -ns 192.168.1.10 --zip
```

`uv` will:

- Create a temporary environment
- Install the tool and dependencies
- Run it in isolation

The environment is cached and reused for performance.
