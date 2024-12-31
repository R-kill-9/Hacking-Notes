Port forwarding is a networking technique that allows external devices to access services on a private network by forwarding traffic from a specified port on a router or firewall to a specific port on an internal device.

# Types of Port Forwarding

### Local Port Forwarding
    
- **Definition**: Forwards a port on the local machine to a port on a remote server.
- **Use Case**: Accessing a remote service that is not exposed to the internet.
```bash
ssh -L [local_port]:[remote_host]:[remote_port] user@ssh_server
```

### Remote Port Forwarding:

- **Definition**: Forwards a port on the remote server to a port on the local machine.
- **Use Case**: Exposing a local service to the remote server.
```bash
ssh -R [remote_port]:[local_host]:[local_port] user@ssh_server
```
### Dynamic Port Forwarding:
    
- **Definition**: Forwards ports dynamically, functioning as a SOCKS proxy.
- **Use Case**: Bypassing firewalls or accessing geo-restricted content.
```bash
ssh -D [local_port] user@ssh_server
```

