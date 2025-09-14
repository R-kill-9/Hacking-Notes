## 1. Prepare Burp on Kali

- Open Burp Suite.
    
- Proxy → Options → Proxy Listeners:
    
    - Add/edit a listener on `0.0.0.0` (All interfaces) port `8080` (or your preferred port).
        
    - Make sure the listener is **enabled**.
        
- If you have Burp Professional and want to intercept HTTPS, export the CA from Proxy → Options → Import / export CA certificate.

## 2. Configure proxy on the iPhone

- Settings → Wi-Fi → tap the network → Configure Proxy → **Manual**.
    
    - Host: `192.168.x.y` (Kali IP)
        
    - Port: `8080`
        
    - Authentication: OFF
        
- Now most HTTP/S traffic will go through Burp.
    

## 3. Install Burp’s CA on the iPhone (critical for HTTPS)

1. In Burp export the certificate in **DER (.cer/.der)** format from Proxy → Options → CA Certificate → Export.
    
2. Serve the file from Kali and download it with Safari on the iPhone:
    
- On Kali, in the directory with `burp_ca.der`:
```bash
python3 -m http.server 8000
```
- On the iPhone open Safari → `http://<KALI_IP>:8000/burp_ca.der` and download.
        
3. iOS will show “Profile Downloaded” or allow installation; install the profile:
    
    - Settings → Profile Downloaded → Install.
        
4. **Trust the root CA** (iOS 10.3+):
    
    - Settings → General → About → Certificate Trust Settings → enable trust for the certificate you installed.
        
5. Verify: in Burp → Proxy → Intercept ON → open an HTTPS page in Safari on the iPhone — you should see the request in Burp.
    

> If Safari download doesn’t work, copy the `.cer` via SCP (if you have OpenSSH) or use Airdrop (if available). On jailbroken devices you can also move the file to `/var/mobile/Media/` and open it with Safari/FileManager.