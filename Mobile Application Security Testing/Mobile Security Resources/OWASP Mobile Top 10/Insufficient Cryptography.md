This category addresses flaws in how mobile applications implement cryptographic functions, often leading to weak data protection. It typically results from using insecure algorithms, improper key storage or flawed encryption workflows.

---

## Common Issues

- Use of deprecated or weak cryptographic algorithms (e.g., DES, MD5)
- Hardcoded encryption keys within the application binary
- Poor or insecure key management strategies
- Improper implementation of cryptographic modes or padding schemes
- Custom or non-standard cryptographic implementations

---

## Weak Encryption Algorithms

Applications that rely on outdated or insecure algorithms (such as DES, RC4, MD5) provide insufficient protection against modern cryptanalysis techniques.



#### Attack Process:

- Reverse engineer the app
- Identify cryptographic primitives in use
- Test encryption strength using known-plaintext or ciphertext attacks

---

## Hardcoded Cryptographic Keys

Hardcoding encryption keys or secrets directly into the app code or resources allows attackers to extract them via static analysis.


#### Attack Process:

- Decompile the APK or IPA using tools like jadx
- Search for hardcoded constants or base64-encoded strings
- Extract keys and use them to decrypt app data

---

## Insecure Key Management

Failing to use secure storage mechanisms (such as Android Keystore or iOS Keychain) exposes cryptographic keys to theft, especially on rooted or jailbroken devices.

#### Attack Process:

- Inspect app’s storage behavior
- Locate keys in shared preferences, files, or hardcoded strings
- Extract and test keys in external tools

---

## Failure to Implement Proper Padding

Incorrect use or omission of padding schemes (e.g., PKCS#7 for block ciphers) leads to encryption flaws or decryption failures.


#### Attack Process:

- Capture encrypted data
- Analyze encryption mode and padding
- Perform padding oracle attacks if applicable