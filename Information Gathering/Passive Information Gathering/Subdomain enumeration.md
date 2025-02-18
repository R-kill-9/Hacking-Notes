Subdomain enumeration through passive information gathering involves collecting publicly available data to identify subdomains associated with a target domain, without directly interacting with the target. 

## Sublist3r
[Sublist3r](https://github.com/aboul3la/Sublist3r) is a  tool that helps gather information about subdomains of a target domain through passive information gathering. It works by querying various public sources such as search engines, DNS servers, and security databases to find subdomains without directly interacting with the target.

| Option   | Description                                                             |
| -------- | ----------------------------------------------------------------------- |
| **`-d`** | Specifies the target domain for subdomain enumeration (mandatory).      |
| **`-o`** | Specifies a file to save the output of the results.                     |
| **`-v`** | Enables verbose mode to display detailed output during the scan.        |
| **`-t`** | Sets the number of threads to speed up the enumeration (default is 10). |
| **`-b`** | Includes the use of Bing as a data source.                              |
| `-e`     | Specifies the search engines to use (e.g., `-e google,yahoo,bing`).     |
```bash
sublist3r -d <target_domain> [options]
```

## Fierce

[Fierce](https://github.com/davidpepper/fierce) is a **DNS reconnaissance tool** used for discovering subdomains and mapping out a target's network. Unlike brute-force tools, Fierce primarily relies on **passive** and **semi-passive** methods to collect information by querying DNS records, without directly engaging with the target.

| Option                          | Description                                                                   |
| ------------------------------- | ----------------------------------------------------------------------------- |
| **`--domain`** `<domain>`       | Specifies the **target domain** for enumeration (**mandatory**).              |
| **`--connect`**                 | Attempts an **HTTP connection** to non-private IPs discovered.                |
| **`--wide`**                    | Scans **entire Class C range** of discovered IPs.                             |
| **`--traverse`** `<n>`          | Scans **nearby IPs** (won’t enter adjacent Class C networks).                 |
| **`--search`** `<domains>`      | Filters results to include only specified **domains** (useful for filtering). |
| **`--range`** `<CIDR>`          | Scans a **specific IP range** (internal networks) using **CIDR notation**.    |
| **`--delay`** `<seconds>`       | Adds a **delay** between lookups to avoid detection or rate limiting.         |
| **`--subdomains`** `<list>`     | Uses a **list of subdomains** for brute-force enumeration.                    |
| **`--subdomain-file`** `<file>` | Uses a **file** containing subdomains (one per line).                         |
| **`--dns-servers`** `<list>`    | Specifies **custom DNS servers** for lookups.                                 |
| **`--dns-file`** `<file>`       | Uses a **file** containing DNS servers (one per line).                        |
| **`--tcp`**                     | Uses **TCP instead of UDP** for DNS queries.                                  |


```bash
fierce --domain <target_domain>
```

**Using a Custom Wordlist:**
```bash
fierce --domain <target_domain> --subdomain-file <custom_list>
```