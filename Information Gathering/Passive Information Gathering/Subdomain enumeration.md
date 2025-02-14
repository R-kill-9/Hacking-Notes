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
