Git repositories can unintentionally expose sensitive information when the `.git/` directory is accessible via HTTP or HTTPS. This can occur due to misconfigured web servers or improper deployment practices.

When exposed, attackers can retrieve not only the current version of the application but also the full development history, including deleted files, credentials, and configuration changes across commits.

A key risk is that even if sensitive data has been removed from the latest version, it may still exist in previous commits.

---

## Extracting exposed repositories with git-dumper

The tool git-dumper is used to reconstruct Git repositories that are accessible over the web but not properly exposed through normal browsing.

It works by recursively downloading the `.git` directory structure, including objects, refs, logs, and configuration files, and then reconstructing a usable local repository.

This is especially useful in penetration testing scenarios where `.git` is exposed but directory listing or direct access is restricted.

---

## Installation process

The tool can be installed by cloning the repository and installing dependencies using Python.

```bash
git clone https://github.com/arthaud/git-dumper.git
cd git-dumper
pip install -r requirements.txt
```

A virtual environment is recommended to avoid dependency conflicts.

---

## Basic usage of git-dumper

To extract a remote exposed repository, provide the target `.git` URL and an output directory where the reconstructed repository will be stored.

```bash
python3 git-dumper.py <url> <directory>
```

Example:

```bash
python3 git-dumper.py http://example.com/.git/ ./dumped-repo
```

Once completed, the output directory will contain a reconstructed Git repository that can be analyzed locally.

---

## Recovering repository history after dumping

After dumping the repository, the next step is to analyze the full Git history. This allows you to recover deleted files, sensitive changes, and previously committed secrets.

First, move into the dumped repository:

```bash
cd dumped-repo
```

Then inspect the commit history:

```bash
git log --oneline
```

This will show all available commits, including older versions that may contain sensitive information that is not present in the latest state.

To inspect a specific commit in detail:

```bash
git show <commit_hash>
```

To restore the entire project state at a specific commit (useful for recovering deleted content):

```bash
git checkout <commit_hash>
```

This places the repository in a detached HEAD state, allowing you to explore the codebase as it existed at that point in time.

If you want to preserve that state for analysis, create a new branch from it:

```bash
git checkout -b analysis <commit_hash>
```

---

## Searching for sensitive information in dumped repositories

Once the repository is reconstructed, it is common to search for sensitive data such as credentials, tokens, or internal domains.

This can be done using recursive search tools:

```bash
grep -r "@domain.com" .
grep -ri "password" .
grep -ri "secret" .
```

This step is critical because sensitive data is often found in configuration files, environment variables, or even within source code comments.

---

## Security impact of exposed Git repositories

When a `.git` directory is exposed, it can lead to severe information disclosure. Attackers may obtain:

- Hardcoded credentials and API keys
    
- Database connection strings
    
- Internal system architecture details
    
- Deleted or hidden source code via commit history
    
- Authentication logic that reveals vulnerabilities
    

Even if sensitive data is removed in the latest version, Git history often retains it indefinitely unless explicitly rewritten.
