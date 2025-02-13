**Proxychains** is a tool used to redirect an application’s network traffic through one or more proxy servers, such as SOCKS4, SOCKS5, or HTTP proxies. This allows you to anonymize your connections, bypass firewalls, or access restricted networks.

For example, when configured with Tor, Proxychains forces all application traffic to route through the Tor network, enhancing anonymity by hiding your IP address and encrypting your internet activity.

## 1. Install Tor

Update your system and install Tor with the following commands:
```bash
sudo apt update
sudo apt install tor -y
```

## 2. Configure Tor as the Default Proxy

**Install Proxychains:**

```bash
sudo apt install proxychains4 -y
```

**Edit the Proxychains Configuration:**

1. Open the configuration file:

```bash
sudo nano /etc/proxychains4.conf
```

2. Ensure the last line in the file is set to:

```bash
socks5  127.0.0.1 9050
```

This setting redirects all traffic through the Tor SOCKS5 proxy.

## 3. Verify Tor is Running and Listening

Before using **Proxychains**, it’s important to verify that **Tor** is running and listening on the correct port.

#### a) Check if Tor is Running

Run the following command to check if **Tor** is running:

```bash
ps aux | grep tor
```

You should see a line like this in the output, indicating that **Tor** is running:

```bash
tor      1234  0.0  0.1  51232  1852 ?        Ss   12:34   0:00 /usr/bin/tor
```

If **Tor** is not running, start it with:

```bash
sudo systemctl start tor
```

#### b) Verify Tor is Listening on Port 9050

To ensure **Tor** is correctly listening on port **9050**, use the following command:

```bash
netstat -tuln | grep 9050
```

You should see something like this:

```bash
tcp   0   0 127.0.0.1:9050   0.0.0.0:*   LISTEN
```

If you don’t see this output, make sure the **Tor** configuration is correct by opening the **Tor configuration file**:

```bash
sudo nano /etc/tor/torrc
```

Look for the line that says `#SocksPort 9050`. Ensure it is **uncommented** (remove the `#` at the beginning).

Then, restart **Tor**:

```
sudo systemctl restart tor
```


## 4. Run Tools Through Proxychains

To run applications through the Tor proxy, use `proxychains4`. For example:

```bash
proxychains4 firefox-esr
```

This command routes all traffic from Firefox through Tor, ensuring anonymity.