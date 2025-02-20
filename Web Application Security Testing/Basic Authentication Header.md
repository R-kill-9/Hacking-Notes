Basic Authentication is a simple authentication scheme used in HTTP requests where the client sends a username and password encoded in **Base64**. While easy to implement, it has security weaknesses that attackers can exploit.

```bash
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

> The encoded value (`dXNlcm5hbWU6cGFzc3dvcmQ=`) is simply **Base64(username:password)**, which is **not encryption** but mere encoding.

## Sniffing Credentials (MITM Attack)

Since Basic Authentication is often used over **unencrypted HTTP**, an attacker can intercept credentials using:

- **Wireshark** (packet sniffing tool)
- **tcpdump** (CLI-based packet capture)
- **Burp Suite** (man-in-the-middle proxy)

Example (captured HTTP request in plaintext):

```bash
GET /admin HTTP/1.1  
Host: example.com  
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=  
```
Using a **Base64 decoder**, an attacker can extract the credentials:
```bash
echo "dXNlcm5hbWU6cGFzc3dvcmQ=" | base64 -d
# Output: username:password
```

## Brute-Forcing Credentials

Since Basic Authentication lacks rate-limiting by default, brute-force attacks are effective.

- **Using Hydra** (Fast parallel brute-forcing tool):
```bash
hydra -L users.txt -P passwords.txt http://example.com -m /admin -V
```

- **Using Burp Suite Intruder**:

1. Capture a request with the **Basic Auth header**.
2. Send it to **Intruder**.
3. Set **payload positions** in the `Authorization` header.
4. Use **Base64 encoded wordlists** for usernames/passwords.
5. Run the attack and look for **200 OK** responses.