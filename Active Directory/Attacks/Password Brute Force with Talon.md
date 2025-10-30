[Talon](https://github.com/Tylous/Talon) is a tool designed to perform automated password guessing attacks while remaining undetected. Talon can enumerate a list of users to identify which users are valid, using Kerberos. Talon can also perform a password guessing attack against the Kerberos and LDAPS (LDAP Secure) services. Talon can either use a single domain controller or multiple ones to perform these attacks, randomizing each attempt, between the domain controllers and services (LDAP or Kerberos).

---

## Installation
Download release for your OS from [releases](https://github.com/optiv/Talon/releases)

The first step as always is to clone the repo. Before you compile Talon you'll need to install the dependencies. To install them, run following commands:

```
go get github.com/fatih/color
go get gopkg.in/jcmturner/gokrb5.v7/client
go get gopkg.in/jcmturner/gokrb5.v7/config
go get gopkg.in/jcmturner/gokrb5.v7/iana/etypeID
go get gopkg.in/ldap.v2
```

Then build it

```
go build Talon.go
```


---


## Core Options

- `-D <domain>`: Fully qualified domain name.
    
- `-H <ip>`: Single domain controller.
    
- `-Hostfile <file>`: File with multiple DCs.
    
- `-U <user>` / `-Userfile <file>`: Single user or list of users.
    
- `-P <password>` / `-Passfile <file>`: Single password or list of passwords.
    
- `-E`: Enumeration mode (valid user discovery).
    
- `-K`: Kerberos-only mode.
    
- `-L`: LDAP-only mode.
    
- `-A <float>`: Authentication attempts per lockout period.
    
- `-Lockout <minutes>`: Lockout period duration.
    
- `-sleep <seconds>`: Delay between attempts.
    
- `-O <file>`: Append results to file.
    

## Enumeration Mode

- Uses Kerberos TGT pre-authentication with an invalid encryption type.
    
- Response codes indicate whether a user exists:
    
    - `KDC_ERR_ETYPE_NOSUPP`: User exists.
        
    - `KDC_ERR_C_PRINCIPAL_UNKNOWN`: User does not exist.
        
- Does not generate login failures, so it avoids lockouts.

```bash
./Talon -D corp.local -H 192.168.1.10 -Userfile users.txt -E
```


---

## Password Guessing Mode

- Alternates between Kerberos and LDAP to distribute traffic.
    
- Can randomize across multiple DCs with `-Hostfile`.
    
- Detects account lockouts and prompts whether to continue.
```bash
./Talon -D corp.local -Hostfile dcs.txt -Userfile valid_users.txt -P "Winter2025" -sleep 1
```


---

## Timing and Lockout Controls

- `-A` limits attempts per lockout window.
    
- `-Lockout` sets the lockout duration in minutes.
    
- `-sleep` adds delay between attempts.

```bash
./Talon -D corp.local -H 192.168.1.10 -Userfile users.txt -Passfile passwords.txt -A 2 -Lockout 30 -sleep 1.5
```

