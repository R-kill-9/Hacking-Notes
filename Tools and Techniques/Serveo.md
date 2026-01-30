**Serveo** is a cloud-based service that allows you to expose local servers to the internet through SSH tunneling without needing to install any additional software. It’s similar to services like Ngrok, but it operates through an SSH connection, making it a very lightweight and easy-to-use option for developers and pentesters alike.

---

## Basic Commands and Usage

#### 1. Exposing a Local Web Server (Port 8080)
```bash
ssh -R 80:localhost:8080 serveo.net
```
- `-R 80:localhost:8080`: This option sets up a reverse tunnel. It tells Serveo to forward traffic from port 80 on Serveo's server to port 8080 on your local machine.
- `serveo.net`: This is the address of the Serveo service that handles the forwarding.

Once connected, Serveo will provide you with a public URL (e.g., `https://yourname.serveo.net`). Any HTTP traffic sent to this URL is forwarded to your local web server running on port 8080.

#### 2. Open the Local Port

Ensure the local service you want to expose is running and that the port (in this case, port 8080) is open and accessible on your machine. This can be verified by:
```bash
python3 -m http.server 8080
```


---

## Using a Custom Subdomain

To use a custom subdomain with Serveo, use the following command:
```bash
ssh -R yoursubdomain:80:localhost:8080 serveo.net
```
This will expose your local service at `https://yoursubdomain.serveo.net`.


---

## Forwarding SSH or Other Services

You can also forward other services, such as SSH, by changing the local port you want to forward. For example, to forward your SSH server (port 22) through Serveo, you would use:
```bash
ssh -R 80:localhost:22 serveo.net
```
You can then access your local machine’s SSH service from the public internet using the provided Serveo URL.