**BloodHound** is an Active Directory (AD) reconnaissance tool that can reveal hidden relationships and identify attack paths within an AD environment.

## First time settings
- create a new neo4j console:
```bash
sudo neo4j console
```
- Connect to localhost:7474 and change the password
	- Default credentials 
		- username: neo4j 
		- password: neo4j
- Download bloodhound-python:
```bash
pip install bloodhound
```
- Add bloodhound to the path. When downloaded it's located at /home/user/.local/bin
```bash
ls /home/_user_/.local/bin
vi ~/.zshrc # Add at the end of the file export PATH=$PATH:/home/user/.local/bin
source ~/.zshrc
```

## Usage
- First, we need to collect the data
```bash
bloodhound-python -c All -u user -p password -d domain_name  -ns target_ip --zip 
```
- Remember to create your node4j console:
```bash
sudo neo4j console
```
- Initialize `BloodHound`
- Upload the data
- Use the menu to see the information
- Is very useful to use the ANALYSIS tool to display visual information


---

## Key Analysis Options
Below is a detailed list of the most important aspects to review, including the BloodHound options and commands that will help you identify and evaluate these attack vectors.

### High-Privilege Accounts (Domain Admins, Enterprise Admins, etc.)

#### **How to Review**:

To identify **high-privilege accounts**, you should focus on certain **groups** and **permissions** that are typically associated with administrative access. In BloodHound, these are usually visualized on the **graph**.

#### **Key Options to Use**:

- **Search for specific groups** in the BloodHound interface:
    
    - **Domain Admins**
    - **Enterprise Admins**
    - **Administrators**
    - **Schema Admins**
    
    You can filter the graph or search the **"Groups"** tab to view these groups and their members.
    
- **Look at the Group Memberships**:
    
    - **Right-click on any user** and inspect their group memberships. If the user is a member of one of these high-privilege groups, they are of interest.
    - Check for **Direct Membership** to **Domain Admins** or **Enterprise Admins**.
    

---

### Outbound Object Control (Lateral Movement)

#### **What is it?**:

**Outbound Object Control** refers to a situation where a user or group can control objects outside their domain, giving attackers the ability to manipulate permissions and escalate privileges across domains.

#### **How to Review**:

1. In the **BloodHound interface**, search for a user, and look at their **Node Info**.
2. Under **Outbound Object Control**, check if the value is different than **0**. This indicates that the user has permissions to affect objects in other systems or domains.

![](bloodhound-outbound-object.png)
#### **Key Options**:

- **Check the "Outbound Object Control" field**:
    - Navigate to **Node Info** when selecting a user. The "Outbound Object Control" field will show whether a user has outbound permissions to affect other objects.
- **Check for paths**:
    - In the **graph** view, you can see direct relationships between users and objects. Right-click on a relationship to explore how a user might escalate privileges via lateral movement.

---

### Group Memberships and Permissions

#### **What to Review**:

Reviewing **group memberships** and **permissions** will help you identify if any user has excessive privileges.

#### **How to Review**:

- **Search for groups**: You can search for the most common privileged groups like **Domain Admins** and see if any user is a member.
- **Right-click on users** in the BloodHound interface to inspect their **group memberships**.
- **Review permissions on shared resources**:
    - Navigate to **Groups** > **Permissions** > **Resources**.
    - Check if any non-administrative users have permissions on sensitive resources (e.g., file shares or domain controllers).

#### **Key Options to Use**:

- **Group Enumeration**:
    - BloodHound will show group memberships when you click on a user or group.
- **Permissions Enumeration**:
    - When selecting a group or user, use the **Permissions** tab to identify who has access to what resources, and whether any excessive permissions have been granted.
    

---

### Service Principal Names (SPNs) and Kerberoasting

#### **What is it?**:

SPNs are used by service accounts to authenticate to AD services. These service accounts can sometimes have weak passwords, making them vulnerable to **Kerberoasting**.

#### **How to Review**:

- **Look for service accounts with SPNs**: These accounts are the prime candidates for **Kerberoasting**.
- **In BloodHound**, navigate to **Service Accounts**. Any service account associated with an SPN is a potential target for Kerberoasting.

#### **Key Options to Use**:

- **Search for SPNs**: BloodHound will show **Service Accounts** when searching for user types. Check if the account has an SPN associated with it.
- **Kerberoasting Pathways**: Identify if the user or group has access to service accounts with SPNs. These service accounts can be targeted by Kerberoasting.


---

### Lateral Movement Paths and Attack Vectors

#### **How to Review**:

BloodHound’s most valuable feature is its ability to display **lateral movement paths**. These paths help identify how an attacker can escalate privileges by moving from one user or machine to another.

#### **Key Options to Use**:

- **Search for Users**:
    
    - Use the **search** function to search for a specific user (e.g., `Olivia`, `Michael`, `Administrator`) and explore how they can escalate.
    - Look at their **owned paths** and **edges** connecting them to other users with higher privileges.
- **Check for Lateral Movement**:
    
    - Once you’ve identified a user, explore the **graph** for paths to **higher-privileged users**. BloodHound will visualize these paths.


---

### Trusts and Cross-Domain Permissions

#### **What is it?**:

Active Directory environments may have **trusts** between domains, and attackers may exploit these to move across domains and escalate privileges.

#### **How to Review**:

- **Search for cross-domain permissions**:
    
    - BloodHound’s **graph** view will display relationships between domains.
    - Right-click on domains or users that belong to different domains to view possible trust relationships.
- **Inspect Cross-Domain Trusts**:
    
    - Use **Trusts** to search for relationships between different Active Directory forests or domains.


---

### Remote Access (WinRM/DCOM)

#### **What is it?**:

**WinRM** (Windows Remote Management) and **DCOM** are remote management protocols that can be exploited for lateral movement across machines.

#### **How to Review**:

1. **Search for users with remote access permissions**.
    - Look for **WinRM** permissions or **DCOM** access in the BloodHound interface under user permissions.
2. **Check session information**: BloodHound will show whether any users have active remote sessions (via WinRM or DCOM).

#### **Key Options to Use**:

- **Remote Access Enumeration**: Search for users with permissions on systems via **WinRM** or **DCOM**.
- **Active Session Enumeration**: BloodHound allows you to visualize remote sessions and which users are interacting with which systems.


---

### Misconfigurations and Delegated Control

#### **What is it?**:

Misconfigurations in **delegated permissions** can create vulnerabilities in the domain, such as over-permissioned accounts or excessive access to sensitive resources.

#### **How to Review**:

- **Check for improper delegation**:
    - In the **graph view**, right-click on groups or users to inspect if they have any unnecessary delegated control.
- **Look for permissions on sensitive objects**:
    - Review the **Permissions** tab for specific users to see whether their permissions are too broad, especially on domain controllers or file servers.

#### **Key Options to Use**:

- **Permissions Enumeration**:
    - Use the **Permissions** tab to review delegated permissions or accidental permissions granted to groups and users.


---

### Active Directory Sessions (Admin Access)

#### **What to Review**:

Check the **Active Directory sessions** to determine which users have administrative access to critical systems.

#### **How to Review**:

- Look for **admin sessions** across the network. BloodHound can display if any high-privileged users are currently logged into critical systems.
- Check the **Node Info** for any session-related information for **administrators** on high-value targets like **domain controllers** or **file servers**.

#### **Key Options to Use**:

- **Session Enumeration**: BloodHound will show session details when inspecting individual user or group nodes.