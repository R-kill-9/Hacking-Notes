[Dehashed](https://github.com/sm00v/Dehashed) is a reconnaissance tool used to search breach data repositories for exposed credentials. It allows analysts to identify cleartext passwords, password hashes, usernames, and associated metadata leaked from historical data breaches.

The platform can be accessed either through the web interface or programmatically via its API using custom scripts.

---

### Credential Discovery

When querying a target domain, Dehashed may return:

- Email addresses
    
- Usernames
    
- Cleartext passwords
    
- Hashed passwords
    
- Associated breach sources (databases)
    

Most discovered credentials are typically old and may not work against externally exposed services or Active Directory authentication. However, password reuse remains common, and valid credentials may occasionally be identified.

Example query execution:

```bash
sudo python3 dehashed.py -q domain.local -p
```
