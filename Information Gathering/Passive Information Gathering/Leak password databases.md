Breach intelligence tools are used during OSINT and security assessments to determine whether information associated with a person, account, or organization has appeared in known data breaches or leaked datasets. They help identify exposed emails, usernames, domains, credentials, and other identifiers.

## HaveIBeenPwned

[Have I Been Pwned (HIBP)](https://haveibeenpwned.com/) is a service used to check whether an email address or other identifiers have appeared in known data breaches.

It is mainly useful for quickly identifying **which services have exposed an account** and what types of data were affected. HIBP generally provides breach information rather than the leaked credentials themselves.

```text
target@example.com
        ↓
HIBP
        ↓
Breaches + affected service + exposed data types
```

## LeakPeek

[LeakPeek](https://leakpeek.com/) is a leak-search platform focused on finding exposed information associated with identifiers such as emails, usernames, domains, IP addresses, names, phone numbers, and hashes.

It can be useful during OSINT investigations to identify whether an identifier appears across different leaked datasets.

```text
Email / Username / Domain / IP
              ↓
          LeakPeek
              ↓
       Related leaked data
```

## DeHashed

[DeHashed](https://dehashed.com/) is a breach-intelligence platform designed to search and correlate information from leaked datasets.

It supports searches using identifiers such as:

```text
Email
Username
Domain
IP address
Phone number
Name
Hash
Password
```

Its main advantage is **cross-referencing different identifiers**. For example, an email address may be associated with usernames, domains, IP addresses, hashes, or other exposed fields.

```text
Email
  ↓
DeHashed
  ↓
Related records
  ├── Username
  ├── Domain
  ├── IP
  └── Hash
```
