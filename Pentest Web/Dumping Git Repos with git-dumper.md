Git repositories often contain sensitive information such as source code, configuration files, credentials, and other private data. Sometimes, these repositories can be accidentally exposed on the web. **git-dumper** is a tool that helps extract the content of these exposed Git repositories, even if they are not directly accessible through normal HTTP/HTTPS methods.

**git-dumper** is particularly useful for cases where the `.git` directory is exposed to the web but direct access to it is restricted. By dumping the repository, an attacker can retrieve the entire repository, including sensitive data that may be of value during a penetration test.

## Installation

To install `git-dumper`, follow these steps (It is possible that you need to configure a virtual environment to successfully install the requirements):

```bash
git clone https://github.com/arthaud/git-dumper.git
cd git-dumper
pip install -r requirements.txt
```

## Usage
- `<url>` is the URL of the exposed Git repository.
- `<directory>` is the directory where the repository contents will be saved.
```bash
python3 git-dumper.py <url> <directory>
```

**Example:** If the repository is exposed at `http://example.com/.git/`, you would run:
```bash
python3 git-dumper.py http://example.com/.git/ /path/to/directory
```

## Possible Vulnerabilities Exposed

By dumping the Git repository, you may find the following types of sensitive information:

1. **Sensitive Credentials**: Configuration files or source code may contain hardcoded passwords, API keys, or other secrets.
2. **Source Code**: The repository may contain proprietary or confidential code that could lead to business logic vulnerabilities.
3. **Configuration Files**: Files like `.env`, `config.json`, `config.php`, or others might contain environment-specific information that could help in exploiting the system.
4. **Commit History**: Historical commits might contain sensitive information (passwords, API tokens, etc.) that was added earlier in the development process.
5. **Exposed Infrastructure Details**: Sometimes, configuration files reveal details about the underlying infrastructure, which can be useful for further attacks.