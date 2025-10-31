Jenkins is an automation server widely used for CI/CD pipelines. Its file structure and security model revolve around the `JENKINS_HOME` directory where configurations, jobs, credentials, and user data are stored. Understanding this layout is key to effective pentesting.

---

## Key Concepts and Structure

- **JENKINS_HOME**: Root directory for Jenkins data (commonly `/var/jenkins_home` or `/var/lib/jenkins`).
- User data, secrets, credentials, and configs are stored here.
- Jenkins stores passwords hashed or encrypted with a master key.
- Some Jenkins versions (e.g., 2.441) have known vulnerabilities like LFI.

---

## Important Jenkins Files & Directories for Pentesting

| File/Folder                                      | Description                                |
| ------------------------------------------------ | ------------------------------------------ |
| `/var/jenkins_home/config.xml`                   | Main Jenkins config file                   |
| `/var/jenkins_home/credentials.xml`              | Stored encrypted credentials               |
| `/var/jenkins_home/secrets/master.key`           | Master key to decrypt credentials          |
| `/var/jenkins_home/secrets/hudson.util.Secret`   | Secret key used in credential encryption   |
| `/var/jenkins_home/users/config.xml`             | List of registered users                   |
| `/var/jenkins_home/users/<user>/config.xml`      | User-specific settings and password hashes |
| `/var/jenkins_home/secrets/initialAdminPassword` | Initial admin password during setup        |


---

## Enumerating Users and Credentials

- If you have access to local files, you can enumerate users in the following route:
```bash
cat /var/jenkins_home/users/config.xml
```
- For each user, check their config for password hashes:
```bash
cat /var/jenkins_home/users/<user_id>/config.xml | grep passwordHash
```
- Passwords are often stored as bcrypt hashes (e.g., starting with `$2a$`).


--- 

## Decrypting Jenkins Credentials

- Another option is trying to access the credentials stored in `credentials.xml`, that are encrypted using AES with keys derived from `master.key` and `hudson.util.Secret`.

- To decrypt:
    1. Extract and read `master.key`
    2. Extract and read `hudson.util.Secret`
    3. Execute the [decrypt script.](https://github.com/bstapes/jenkins-decrypt)





