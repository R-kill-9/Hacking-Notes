The **OWASP MASVS (Mobile Application Security Verification Standard)** is the industry standard for mobile app security. It can be used by mobile software architects and developers seeking to develop secure mobile applications, as well as security testers to ensure completeness and consistency of test results.

To complement the MASVS, the OWASP MAS project also provides the [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG), the [OWASP Mobile Application Security Weakness Enumeration (MASWE)](https://mas.owasp.org/MASWE) and the [OWASP MAS Checklist](https://mas.owasp.org/checklists) which together are the perfect companion for verifying the controls listed in the OWASP MASVS and demonstrate compliance.

> I highly recommend downloading the **OWASP MAS Checklist** and using it as a guide during mobile app penetration tests. 

## OWASP MAS Checklist[¶](https://mas.owasp.org/checklists/#owasp-mas-checklist "Permanent link")

![](https://mas.owasp.org/assets/mas_checklist.png)

The OWASP Mobile Application Security Checklist contains links to the MASTG test cases for each MASVS control.

- **Security Assessments / Pentests**: ensure you're at least covering the standard attack surface and start exploring.
- **Standard Compliance**: includes MASVS and MASTG versions and commit IDs.
- **Learn & practice** your mobile security skills.
- **Bug Bounties**: go step by step covering the mobile attack surface.


## OWASP MASTG[¶](https://mas.owasp.org/MASTG/#owasp-mastg "Permanent link")

The **OWASP Mobile Application Security Testing Guide (MASTG)** is a comprehensive manual for mobile app security testing and reverse engineering. It describes technical processes for verifying the controls listed in the [OWASP MASVS](https://mas.owasp.org/MASVS) through the weaknesses defined by the [OWASP MASWE](https://mas.owasp.org/MASWE).


## OWASP MASVS[¶](https://mas.owasp.org/MASVS/#owasp-masvs "Permanent link")
The **OWASP MASVS (Mobile Application Security Verification Standard)** is the industry standard for mobile app security. It can be used by mobile software architects and developers seeking to develop secure mobile applications, as well as security testers to ensure completeness and consistency of test results.

To complement the MASVS, the OWASP MAS project also provides the [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG), the [OWASP Mobile Application Security Weakness Enumeration (MASWE)](https://mas.owasp.org/MASWE) and the [OWASP MAS Checklist](https://mas.owasp.org/checklists) which together are the perfect companion for verifying the controls listed in the OWASP MASVS and demonstrate compliance.


#### The MASVS Control Groups[¶](https://mas.owasp.org/MASVS/#the-masvs-control-groups "Permanent link")

The standard is divided into various groups of controls, labeled **MASVS-XXXXX**, that represent the most critical areas of the mobile attack surface:

- **MASVS-STORAGE**: Secure storage of sensitive data on a device (data-at-rest).
- **MASVS-CRYPTO**: Cryptographic functionality used to protect sensitive data.
- **MASVS-AUTH**: Authentication and authorization mechanisms used by the mobile app.
- **MASVS-NETWORK**: Secure network communication between the mobile app and remote endpoints (data-in-transit).
- **MASVS-PLATFORM**: Secure interaction with the underlying mobile platform and other installed apps.
- **MASVS-CODE**: Security best practices for data processing and keeping the app up-to-date.
- **MASVS-RESILIENCE**: Resilience to reverse engineering and tampering attempts.
- **MASVS-PRIVACY**: Privacy controls to protect user privacy.