PHP Type Juggling refers to PHP’s automatic type conversion when using **loose comparison operators** (`==` or `!=`).  
When two values of different types are compared, PHP attempts to convert them into a common type before evaluating equality.  
This behavior can lead to **authentication bypass**, **logic manipulation**, and **hash comparison vulnerabilities**.


---

## Loose vs Strict Comparison

#### Loose Comparison (=\=)

- Performs type coercion.
- Converts both operands to a common type (often numeric).
- Can produce unexpected TRUE results.

#### **Strict Comparison (=\==)

- No type conversion.
- Compares both **value and type**.
- Safe for authentication, token validation, and security‑critical logic.

---

## Magic Hashes

Certain strings that look like scientific notation are interpreted as numeric values by PHP during loose comparison.

```
0e123456
0e987654321
```

PHP interprets these as:

```
0 × 10^123456 = 0
```

**Dangerous Comparisons**

```php
"0e1234" == "0e9999"   // TRUE
"0e1234" == 0          // TRUE
"0e1234" == "0"        // TRUE
```

This becomes critical when comparing **hashes**, especially MD5 or SHA1 values that accidentally produce a magic‑hash pattern.


---

## Impact on Authentication

If an application uses loose comparison for token or password validation:

```php
if ($user_token == $_GET['token']) {
    // authenticated
}
```

An attacker can bypass authentication by supplying:

- A magic hash (`0e123456`)
- A boolean (`true`, `false`)
- Numeric values (`0`, `1`)
- Empty arrays (`[]`)

Because PHP will coerce types, the comparison may evaluate to TRUE even when the values are not equal.

---

## Fuzzing Attack

To test a parameter for Type Juggling weaknesses a fuzzing attack with special wordlists can be used:

```bash
ffuf -c -u http://target.com/user?token=FUZZ \
     -w php_loose_comparison.txt \
     -fw 4
```

- `-fw 4` filters responses with 4 words, helping detect anomalies.
- A different response length often indicates a bypass or altered logic path.
