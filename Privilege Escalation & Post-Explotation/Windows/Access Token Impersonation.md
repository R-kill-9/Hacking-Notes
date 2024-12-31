A **security token** is a data structure used by the Windows operating system to represent a user's identity, permissions, and privileges. Tokens are created when a user logs in to the system, and they are associated with processes the user starts. These tokens are used by the system to determine which resources a user can access and what actions they can perform.

Security tokens contain the following key information:

- **User SID (Security Identifier)**: Unique identifier for the user or group.
- **Group SIDs**: Identifiers for the groups the user belongs to.
- **Privileges**: Specific rights granted to the user (e.g., shutdown the system, change system time).
- **Owner**: The owner of the token, which can be used to control access to certain resources.Security tokens contain the following key information:

There are two main types of tokens:

1. **Primary Tokens**: Assigned to a process when the user logs in and reflects the identity of the user.
2. **Impersonation Tokens**: These are created when one process assumes the identity of another process (e.g., a service impersonating a user).

To execute a Token Impersonation attack, the following privileges are necessary:

- **SeAssignPrimatyToken**
- **SeCreateToken**
- **SeImpersonatePrivilege**

## Attacking with Incognito (Metasploit) 
**Incognito** is a powerful Metasploit module specciallly used for token impersonation.

1. **Start a Meterpreter Session and Load the Module**
Before you can use Incognito for token impersonation, you need to have an active Meterpreter session. After, you can load the module.

```bash
load incognito
```

2.  **List Available Tokens**

After loading **Incognito**, the next step is to list the available tokens. These are the tokens for the processes running on the system, which you can potentially impersonate.

```bash
list_tokens -u
```

4. **Impersonate a Token**

Once you’ve identified a suitable token to impersonate (such as **Administrator** or **SYSTEM**), use the following command to impersonate it:

```bash
impersonate_token <token_name>
```

Sometimes it would be necessary adding a `\` character between the domain and the user: `DOMAIN\\USER`.