This vulnerability arises when applications integrate **third-party software** (e.g., SDKs, libraries, services) **without performing proper security auditing, testing, or validation**. Attackers can exploit this trust to inject malicious code during development, build, or deployment stages.

---

## Malicious Third-Party SDK

Apps often rely on SDKs for analytics, ads, or other functionality. If an SDK is compromised, it can act as a vector to **exfiltrate sensitive user data** or introduce vulnerabilities.

- Developers integrate third-party SDKs without security review.
- SDK contains hidden malicious logic or unintended data collection.

#### Attack Steps:

1. Attacker publishes a third-party SDK with **malicious payload**.
2. App developers integrate the SDK **without auditing its behavior**.    
3. When the app is deployed, user data is leaked to the attacker's infrastructure.


---


## Compromised Build Server

If the **CI/CD pipeline** or build infrastructure is improperly secured, attackers can inject backdoors during the build process.

- Poorly protected Jenkins, GitHub Actions, or other CI/CD environments.
- Attacker compromises the build process, modifies the output `.apk` or `.ipa`.

#### Attack Steps:

1. Attacker exploits weak credentials or exposed ports on a build server.
2. Injects malicious code or binaries into the compiled app.
3. The tampered app is **signed and published** to users.


---

## Tampered Open Source Libraries

Apps using open-source dependencies may unknowingly pull in **tampered or vulnerable code**, especially if there's **no version pinning or hash verification**.

- An attacker compromises a legitimate GitHub repo or package registry.
- Malicious code is introduced in a new library release.

#### Attack Steps:

1. Attacker gains access to the library repository.
2. Injects obfuscated or backdoored logic.
3. App developers update their dependencies, unknowingly integrating the malicious version.


---

## Dependency Confusion

A common supply chain attack where the attacker uploads a **malicious package** to a public registry using the **same name** as an internal/private package.

- Happens when developers use private package names but do not properly scope or configure package sources.
- Build tools may **prioritize the public version** over the private/internal one.

#### Attack Steps:

1. Attacker registers a public package named `internal-lib-core`.
2. The app mistakenly downloads this from the public registry during build.
3. Malicious code is executed at runtime.