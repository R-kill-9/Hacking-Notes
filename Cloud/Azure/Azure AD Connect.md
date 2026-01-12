> I recommend reading these notes for a deeper understanding:  
[https://blog.xpnsec.com/azuread-connect-for-redteam/](https://blog.xpnsec.com/azuread-connect-for-redteam/)

**Azure AD Connect** is a Microsoft tool used to synchronize on‑premises Active Directory with Azure Active Directory. It enables users to authenticate to cloud services such as Azure, Office 365, and SharePoint using their on‑prem AD credentials. Because it bridges on‑prem and cloud identity, it becomes a high‑value target for attackers who gain access to the server where it is installed.

---

## Exploitation Theory

Azure AD Connect **stores the on-premises Active Directory service account credentials (MSOL account)**. Although the password is omitted from the plaintext XML (`private_configuration_xml`), it is actually stored **encrypted** in the Azure AD Connect LocalDB database.

This encrypted credential can be **programmatically decrypted** by:

- Reading key material from the LocalDB instance
- Loading Microsoft’s internal cryptographic library (`mcrypt.dll`)
- Decrypting the `encrypted_configuration` field

This technique is applicable during a pentest **when your current user**:

- Is Local Administrator on the Azure AD Connect server, or
- Is a member of the local `ADSyncAdmins` group, or
- Can execute code in the context of the ADSync service

Under these conditions, the MSOL account password can be recovered in cleartext.

---

## **Practical Exploitation**

The following exploit automates the credential extraction process:

[Azure AD Connect Credential Extraction Script](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1)

Example usage:

```
Evil-WinRM PS C:\users\mhope\downloads> upload Azure-ADConnect.ps1

Evil-WinRM PS C:\users\mhope\downloads> import-module .\Azure-ADConnect.ps1

Evil-WinRM PS C:\users\mhope\downloads> get-module
```

Once executed with sufficient privileges, the script decrypts and reveals the **MSOL service account credentials**, which can then be used to escalate privileges (e.g., via DCSync).