**SUID (Set User ID)** binaries are executable files in Unix/Linux systems that, when run, execute with the privileges of the file's owner rather than the user executing it.

- This allows temporary elevation of privileges to perform specific tasks that require higher permissions.
- For example, the `passwd` command uses SUID to modify the `/etc/shadow` file (which is only accessible by `root`), even when executed by a non-privileged user. 
 
---

## Exploiting SUID Binaries
#### Recognize them in a file listing  
Use `ls -l` to spot the SUID bit (represented by an `s` in the owner's permissions).  

```bash
-rwsr-xr-x 1 root root 12345 Sep 10 10:00 /usr/bin/passwd
```

#### Enumeration using find
This command is used to search for files and directories within a specified directory hierarchy. It searches recursively through the directory structure, starting from the given directory, and matches files and directories based on specified criteria.

- Parameters:
	 - `-name <pattern>`: Matches files and directories with the specified name pattern.
	- `-type <type>`: Matches files or directories of the specified type, such as `f` for regular files or `d` for directories.
	- `-size <size>`: Matches files based on size, such as `+10M` for files larger than 10 megabytes or `-100K` for files smaller than 100 kilobytes.
	- `-user <username>`: Matches files owned by the specified username.

```bash
find [path] [expression]
```

It can be useful to discover all the files that can be executed with root privileges because of their SUID bit is enabled.

- **`-perm 4000`**: Searches for files with permissions exactly `4000`, including only files with the SUID bit set and no other permissions.
- **`-perm -4000`**: Searches for files with at least the SUID bit set, regardless of other permissions. For example, it will find files like `rwsr-xr-x`.

```bash
find / -perm -4000 2>/dev/null
```

#### Check unusual binaries

- Compare the results with standard lists (e.g., GTFOBins: https://gtfobins.github.io/).
- Uncommon binaries might be vulnerable or unnecessary.