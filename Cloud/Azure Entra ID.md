**Azure Entra ID is a Microsoft's cloud-based identity and access management (IAM) service.** It provides secure authentication, authorization, and identity governance across cloud and hybrid environments.


---

## Key Features

- **Single Sign-On (SSO):** Users log in once and access multiple apps without re-authentication.
- **Multi-Factor Authentication (MFA):** Adds a second layer of identity verification.
- **Conditional Access:** Enforces access rules based on location, device, risk level, etc.
- **Role-Based Access Control (RBAC):** Assigns permissions based on user roles.
- **Identity Protection:** Detects and responds to risky sign-ins and compromised accounts.
- **Privileged Identity Management (PIM):** Controls and audits access to sensitive roles.



---


## Enumeration and Exploitation with Roadtools

**Roadtools** can be used to enumerate and analyze Azure Entra ID tenants by gathering data on users, roles, applications, and service principals. Here's a technical breakdown of how to do it based on the methodology described in the referenced article.

#### 1. Authenticate and Obtain Tokens

Use `roadtools-auth` to authenticate and store access tokens locally.

```bash
roadrecon auth -u <user>@tenant.onmicrosoft.com -p <password>
```
- Authenticates using username and password.

- Stores access tokens locally for use with other modules.


#### Gather Tenant Data
```bash
roadrecon gather
```
- Collects all accessible directory data using Microsoft Graph API.

- Stores results in a local SQLite database (`roadrecon.db`).

#### Explore the Data
```bash
roadrecon gui
```
- Launches a local web interface at `http://localhost:5000`.

- Allows browsing of users, groups, roles, applications, service principals, and more


---

## BloodHound

Roadtools includes an experimental plugin that integrates Azure Entra ID data into a **BloodHound-compatible Neo4j database**, enabling visual exploration of cloud identities and relationships.

This plugin reads objects from the `roadrecon.db` SQLite database and converts them into BloodHound-style nodes and edges. When used with a custom fork of the BloodHound interface, it allows you to:

- Visualize **users**, **groups**, and **roles** in Azure Entra ID.
    
- Map **role assignments** and **group memberships**.
    
- Link **cloud identities** with **on-prem Active Directory users** in hybrid environments.