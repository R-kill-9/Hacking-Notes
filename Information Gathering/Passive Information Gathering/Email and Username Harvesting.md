**Email harvesting** is the process of collecting email addresses from various online sources, often for marketing or malicious purposes. It involves extracting email addresses from websites, forums, social media, or public directories using manual methods or automated tools like web scrapers.

---
## User Scanner

[User Scanner](https://github.com/kaifcodec/user-scanner) is an OSINT tool designed to investigate **email addresses and usernames** across multiple online platforms. It can identify profiles, usernames, aliases, publicly exposed email addresses, and other information that can be used to perform further OSINT pivots.

It is particularly useful when an **email address or username is already available as a starting point**.

|Option|Description|
|---|---|
|**`-u <username>`**|Searches for a username across supported platforms.|
|**`-e <email>`**|Investigates an email address and searches for related information.|
|**`--cross-scan`**|Performs additional pivots between discovered usernames, emails, aliases, and profiles.|
|**`--help`**|Displays the available options and commands.|

Search for a username:

```bash
user-scanner -u johndoe
```

Investigate an email:

```bash
user-scanner -e johndoe@gmail.com
```

Perform a cross-scan:

```bash
user-scanner -u johndoe --cross-scan
```

Or start from an email:

```bash
user-scanner -e johndoe@gmail.com --cross-scan
```

Investigation flow:

```text
Username / Email
       ↓
  User Scanner
       ├── Profiles
       ├── Usernames
       ├── Aliases
       ├── Public emails
       └── Platform information
              ↓
        Further pivots
```


---

## Sherlock

[Sherlock](https://github.com/sherlock-project/sherlock) is an OSINT tool specialized in searching for **usernames** across many online platforms. Given a username, it checks whether that username exists on supported websites and services.

It is particularly useful when a **username is already available as a starting point**.

|Option|Description|
|---|---|
|**`sherlock <username>`**|Searches for the username across supported platforms.|
|**`--print-found`**|Displays only the profiles that were found.|
|**`--output <file>`**|Saves the results to a file.|
|**`--csv`**|Saves the results in CSV format.|

Example:

```bash
sherlock username
```

Save the results:

```bash
sherlock username --output results.txt
```

Investigation flow:

```text
Username
    ↓
Sherlock
    ├── GitHub
    ├── Reddit
    ├── X
    ├── Instagram
    ├── etc.
    └── Other platforms
```

---

## MailAccess

[MailAccess](github.com/KatrielMoses/MailAccess) is an OSINT tool designed to investigate information starting from an **email address**. It can collect publicly available information related to an email and perform different pivots to discover possible identities, usernames, platforms, and other indicators.

It is particularly useful when an **email address is the starting point** of an investigation.

|Option / Module|Description|
|---|---|
|**`investigate <email>`**|Starts an investigation on an email address.|
|**`email_discovery`**|Searches for possible email addresses related to information discovered during the investigation.|
|**`username_platforms`**|Checks for possible usernames across different platforms.|
|**`permutation_discovery`**|Generates possible email variations based on names and other discovered information.|

```bash
mailaccess investigate user@example.com
```

Investigation flow:

```text
Email
  ↓
MailAccess
  ├── Public information
  ├── Possible names
  ├── Usernames
  ├── Other emails
  └── Related platforms
```


---

## Harvester

[theHarvester](https://github.com/laramies/theHarvester) is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red team assessment or penetration test. It performs open source intelligence (OSINT) gathering to help determine  a domain's external threat landscape. The tool gathers names, emails, IPs, subdomains, and URLs by using  
multiple public resources.

| Option | Description |
|--------|-------------|
| **`-d <domain>`** | Specifies the target domain to search (e.g., `example.com`). |
| **`-b <source>`** | Defines the source to query (e.g., Google, Bing, LinkedIn, etc.). Use `-b all` to query all available sources. |
| **`-l <limit>`** | Sets the maximum number of results to retrieve (optional). |
| **`-f <filename>`** | Exports results to a file (e.g., PDF or HTML). |

```bash
theHarvester -d <domain> -b <source>
```

