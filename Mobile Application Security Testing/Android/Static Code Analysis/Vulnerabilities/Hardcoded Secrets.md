**Hardcoded secrets** refer to sensitive information embedded directly in the source code. These secrets include API keys, credentials (usernames/passwords), encryption keys and sensitive URLs.

Storing secrets in code can expose critical data to attackers, especially when the app is decompiled or the code is leaked. This can lead to unauthorized access, privilege escalation, or data breaches.

#### Common types of hardcoded secrets

- API keys (e.g. Google Maps, Firebase)
- Database credentials
- Encryption keys (AES, RSA)
- Authentication tokens
- Internal endpoints or admin URLs

#### Example 1: Hardcoded API Key in Java
```java
public class WeatherService {
    private static final String API_KEY = "AIzaSyD12345FakeKey98765";  // hardcoded API key

    public String getWeather(String city) {
        String url = "https://api.weather.com/v3/weather?apikey=" + API_KEY + "&q=" + city;
        // logic to perform HTTP request
        return fetch(url);
    }
}
```


#### Example 2: Hardcoded credentials and URL in Kotlin
```kotlin
object Config {
    const val DB_USER = "admin"
    const val DB_PASSWORD = "p@ssw0rd"
    const val API_URL = "https://internal.api.example.com/v1/"
}
```

These values are visible to anyone who decompiles the APK, making them vulnerable to misuse.

## Regex patterns for secret detection

You can use regular expressions to scan your codebase for hardcoded secrets. Below are examples of regexes used to detect common patterns:


```r
# API keys (generic alphanumeric tokens)
(?i)(api_key|apikey|token|secret|access_token)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']

# AWS Access Key ID
AKIA[0-9A-Z]{16}

# Google API Key
AIza[0-9A-Za-z\-_]{35}

# Basic auth credentials (user:pass)
["'][a-zA-Z0-9._%+-]+:[a-zA-Z0-9!@#$%^&*()_+=-]+["']

# Password assignment
(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']
```


These regex patterns can be used in tools or manually tested using regex101 for validation.
