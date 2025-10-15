**Web browsers** often store valuable information such as history, bookmarks, saved logins, and session tokens. By analyzing these artifacts, an attacker may uncover credentials, internal application URLs, or administrative portals that can be leveraged to escalate privileges or pivot further into the environment.

### Step 1: Identify Browser Artifacts

Check if the target machine has a browser installed and locate its profile data. For Firefox, user data is typically stored under the `.mozilla` directory:

```bash
ls -la ~/.mozilla/
cd ~/.mozilla/firefox/
```

Each profile has its own folder (e.g., `b2rri1qd.default-release`). Navigate into the correct profile directory:
```bash
cd b2rri1qd.default-release
```

### Step 2: Inspect Firefox Databases

Firefox stores history, bookmarks, and sometimes credentials in SQLite databases. Use `sqlite3` to explore them:
```bash
sqlite3 places.sqlite
.tables
```
- `moz_places` → browsing history (URLs).
    
- `moz_bookmarks` → saved bookmarks.


Query bookmarks:
```bash
select * from moz_bookmarks;
```

### Step 3: Extract Sensitive Information

- Bookmarks and history may contain **URLs to internal systems**, **admin panels**, or even **credentials embedded in query strings**.
    
- Attackers can leverage this information to pivot or escalate privileges.
    

Example findings:

- Bookmarks pointing to `http://intranet/admin`
    
- Saved links with usernames or tokens in the URL
    
- Evidence of web applications used by privileged accounts