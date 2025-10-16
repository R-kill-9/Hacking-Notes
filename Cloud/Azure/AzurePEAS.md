[AzurePEAS](https://github.com/carlospolop/CloudPEASS) is a post-exploitation enumeration tool for Microsoft Azure and Microsoft 365 environments. It is designed to identify effective permissions of a compromised principal (user or service principal), highlight potential privilege escalation paths, and enumerate sensitive resources. It leverages Microsoft Graph and Azure Resource Manager (ARM) APIs.


---

## 1. Authentication and Token Acquisition

AzurePEAS does not perform interactive login itself; you must provide valid tokens.

```bash
# Login to Azure tenant (with or without subscriptions)
az login --tenant <tenant_id> --allow-no-subscriptions

# Get Microsoft Graph token
az account get-access-token --resource-type ms-graph --tenant <tenant_id>
# At this point is possible that you need to log in using the browser

# Get ARM token (only if subscriptions exist)
az account get-access-token --resource-type arm --tenant <tenant_id>
```

- **Graph token**: required for Entra ID (Azure AD) and Microsoft 365 enumeration.
    
- **ARM token**: required for Azure Resource Manager enumeration (VMs, storage, etc.).
    
- If no subscriptions exist, ARM token is not needed and AzurePEAS will skip ARM analysis.


---

## 2. Running AzurePEAS

You can run the tool with one or both tokens:
```bash
# Graph-only analysis
python3 AzurePEAS.py --graph-token "$GRAPH_TOKEN" --out-json-path /tmp/azurepeas.json

# Graph + ARM analysis
python3 AzurePEAS.py --graph-token "$GRAPH_TOKEN" --arm-token "$ARM_TOKEN" --out-json-path /tmp/azurepeas.json
```

- `--graph-token`: JWT access token for Microsoft Graph.
    
- `--arm-token`: JWT access token for ARM.
    
- `--out-json-path`: saves results in JSON for later review.

This confirms the identity under which enumeration will run.


---

## 4. Graph API Enumeration

AzurePEAS queries Microsoft Graph endpoints to collect:

- **User details**: display name, email, object ID.
    
- **Group memberships**: groups where the user is a member or owner.
    
- **Owned groups**: critical because ownership can allow privilege escalation.
    
- **Directory roles**: checks if the user or owned groups are members of privileged roles.
    
- **Conditional Access Policies**: if accessible, enumerates restrictions applied to the account.
    
- **Application permissions**: delegated and application permissions granted to the principal.
    


---

## 5. ARM API Enumeration (if ARM token provided)

AzurePEAS queries ARM endpoints to discover:

- **Subscriptions**: lists all accessible subscriptions.
    
- **Resource groups**: enumerates groups within subscriptions.
    
- **Resources**: VMs, storage accounts, key vaults, functions, etc.
    
- **IAM policies**: attempts to retrieve role assignments and custom roles.
    

This step identifies misconfigurations such as overly permissive roles or service principal assignments.


---

## 6. Permission Analysis

AzurePEAS classifies discovered permissions into categories:
```bash
Very Sensitive Permissions
- Direct privilege escalation or credential access (e.g., User Administrator, Privileged Role Administrator).

Sensitive Permissions
- Indirect escalation or data exposure (e.g., Group Owner, Application Administrator).

Regular Permissions
- Common, low-risk permissions (e.g., read-only access).
  ```



---

## 7. Example Findings

**Group Ownership**
```bash
Privilege Escalation via Group Ownership Manipulation
- Owners can add themselves or others to privileged groups.
- Escalation possible if the group is linked to admin roles.
```
**Data Exfiltration**
```bash
Access and Exfiltrate Sensitive Data from Group Resources
- Owners can access SharePoint, OneDrive, Teams, and conversations.
- Risk of sensitive data leakage.
```
**Group Settings Modification**
```bash
Modify Group Settings to Enable Data Leakage or External Sharing
- Owners can relax access controls or enable external sharing.
- May expose internal data to unauthorized users.
```

