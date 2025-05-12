**Frida** provides an easy-to-use framework for hooking into a running application and modifying its behavior. Below, we’ll explore some practical examples and commands for hooking functions in a live process, with a focus on real-world use cases for security testing.

> Useful content:
> [Hooking Java Methods with Frida](https://www.youtube.com/watch?v=RJXsvAjZl9U&t=330s)
> [Hooking Native Android Methods with Frida](https://www.youtube.com/watch?v=N2JtRXCofUU&t=370s)

## Basic Hooking in Java (Android)

To hook into Java code within an Android app, we can use the `Java.use()` function, which allows us to access a class and its methods.

#### Example: Hooking into a Login Function

Let's assume you want to hook into a login function that checks if the user’s credentials are correct:

```javascript
Java.perform(function () {
    var LoginActivity = Java.use('com.example.app.LoginActivity');  // Replace with actual class path
    LoginActivity.login.implementation = function (username, password) {
        console.log('Original username: ' + username);
        console.log('Original password: ' + password);

        // Modify the arguments before passing them to the original function
        var modifiedUsername = 'attacker';
        var modifiedPassword = 'password123';

        console.log('Modified username: ' + modifiedUsername);
        console.log('Modified password: ' + modifiedPassword);

        // Call the original function with modified arguments
        return this.login(modifiedUsername, modifiedPassword);
    };
});
```
**What it does**: This script hooks into the `login()` method in the `LoginActivity` class. It intercepts the username and password arguments, modifies them, and then calls the original function with the new values. This is useful for bypassing login checks.

## Hooking Native Methods (Android / iOS)

Frida also allows hooking into native functions written in C or C++. This is useful for reverse engineering native libraries or working with sensitive operations not exposed to Java.

#### Example: Hooking a Native Function

Let’s say you want to hook into a function like `strcpy()` in a native app:
```javascript
var moduleName = 'libc.so';  // Targeting the C library on Android
var strcpy = Module.findExportByName(moduleName, 'strcpy');  // Find the export for strcpy()

Interceptor.attach(strcpy, {
    onEnter: function (args) {
        console.log('Source string: ' + Memory.readUtf8String(args[0]));  // Read the string passed as the first argument
        console.log('Destination address: ' + args[1]);  // Destination buffer
    },
    onLeave: function (retval) {
        console.log('Original return value: ' + retval);
        // Modify the return value if necessary
    }
});
```
**What it does**: This script hooks into the `strcpy()` function in the `libc.so` library. When the function is called, it logs the source string and destination address, which is helpful for understanding how sensitive data is being copied or handled.

## Bypassing SSL Pinning Using Hooking

SSL pinning is a common security mechanism used in mobile apps to prevent man-in-the-middle (MITM) attacks. Frida can be used to bypass SSL pinning by hooking into the relevant methods that perform the pinning checks.

#### Example: Bypassing SSL Pinning on Android

```javascript
Java.perform(function () {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    // Bypass the SSL certificate validation check
    TrustManagerImpl.checkServerTrusted.implementation = function (chain, authType) {
        console.log('SSL Pinning bypassed!');
        return;  // Just return without checking the certificate chain
    };
});
```

**What it does**: This script hooks into the `checkServerTrusted()` method of `TrustManagerImpl`, which is responsible for validating the server's SSL certificate. By overriding this method to return immediately, the SSL pinning mechanism is bypassed, allowing you to perform MITM attacks or inspect network traffic.

## Intercepting API Calls

Sometimes, you may want to intercept API calls made by an app to examine the data being sent or received. This can be done by hooking the network-related methods in the app.

#### Example: Intercepting HTTP Requests
```javascript
Java.perform(function () {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');  // For apps using OkHttp
    var Request = Java.use('okhttp3.Request');

    OkHttpClient.newCall.implementation = function (request) {
        console.log('Request URL: ' + request.url().toString());
        
        // Optionally modify the request before it is sent
        var modifiedRequest = request.newBuilder().header('User-Agent', 'Frida').build();
        
        return this.newCall(modifiedRequest);  // Call the original function with the modified request
    };
});
```

**What it does**: This script hooks into the `newCall()` method of `OkHttpClient`, which is responsible for making HTTP requests. It logs the URL of the request and modifies the request headers (e.g., adding a custom `User-Agent` header) before the request is sent. This can be useful for analyzing or manipulating API requests and responses.


## Tracing Function Calls in Real-Time

You can also use Frida to trace the execution of specific functions or methods in real time, which can help in understanding how an app behaves and identifying security issues.

#### Example: Tracing Function Calls
```javascript
Java.perform(function () {
    var MainActivity = Java.use('com.example.app.MainActivity');
    
    // Trace every time the target method is called
    MainActivity.onCreate.implementation = function () {
        console.log('MainActivity.onCreate() called');
        this.onCreate();  // Call the original function
    };
});
```
**What it does**: This script hooks into the `onCreate()` method of `MainActivity` and logs every time the method is called. It can be useful for tracing the flow of an app and understanding how different components interact.