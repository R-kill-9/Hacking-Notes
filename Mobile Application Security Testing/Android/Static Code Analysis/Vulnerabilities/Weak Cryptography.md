Weak cryptography refers to the use of insecure or outdated encryption practices, which attackers can break or bypass. This includes:

- **Hardcoded encryption keys**
- **Use of outdated or broken algorithms** such as:
    - MD5
    - SHA-1
    - DES
    - ECB mode for block ciphers

These practices can lead to compromise of confidential information, especially if the app handles credentials, tokens or PII.

---

#### Common Weak Algorithms (Do Not Use)

- MD5: Vulnerable to collision attacks    
- SHA-1: Broken by researchers (e.g., SHAttered)
- DES: Small key size (56-bit)
- AES in ECB mode: Reveals patterns in plaintext

---
#### Example 1: Java code using Cipher with AES

```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoExample {
    public static void encrypt(String data) throws Exception {
        String key = "1234567890123456"; // Hardcoded key (INSECURE)
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB is insecure
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println("Encrypted: " + new String(encrypted));
    }
}
```

#### Example 2: Kotlin code using Cipher

```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

fun encrypt(data: String) {
    val key = "1234567890123456" // INSECURE hardcoded key
    val secretKey = SecretKeySpec(key.toByteArray(), "AES")
    
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding") // ECB is insecure
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val encrypted = cipher.doFinal(data.toByteArray())
    println("Encrypted: ${String(encrypted)}")
}
```


#### Example 3: Swift using CommonCrypto


```swift
import CommonCrypto

func md5Hash(data: String) -> String {
    let messageData = data.data(using:.utf8)!
    var digestData = Data(count: Int(CC_MD5_DIGEST_LENGTH))

    _ = digestData.withUnsafeMutableBytes { digestBytes in
        messageData.withUnsafeBytes { messageBytes in
            CC_MD5(messageBytes.baseAddress, CC_LONG(messageData.count), digestBytes.bindMemory(to: UInt8.self).baseAddress)
        }
    }
    return digestData.map { String(format: "%02hhx", $0) }.joined()
}
```



#### Example 4: Objective-C using CommonCrypto with SHA-1
```swift
#import <CommonCrypto/CommonDigest.h>

NSString* sha1Hash(NSString* input) {
    const char *str = [input UTF8String];
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(str, (CC_LONG)strlen(str), result); // SHA-1 is insecure

    NSMutableString *hash = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    return hash;
}
```



## Regex (grep) to detect usage of weak algorithms or hardcoded keys

You can use this regex to scan source code or decompiled smali/java files:
```bash
grep -Ei '(AES|DES|RSA|MD5|SHA1|SHA-1)' -r ./sourcecode/
```




