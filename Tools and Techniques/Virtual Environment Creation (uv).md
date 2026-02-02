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
## Usage

#### Project Initialization 

The first step when starting a new project with uv is to initialize it:

```bash
uv init
```

#### Adding Libraries to Your Project

Once your project is initialized with `uv init`, you can add dependencies using:

```bash
uv add <package>
```

This will:

- Install the package into the project’s virtual environment
    
- Update the `pyproject.toml` and lockfile
    
- Make the package available for your scripts


#### Running a script with temporary dependencies

You can run a script and install extra packages only for that execution:

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


