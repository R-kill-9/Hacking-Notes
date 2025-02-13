## OpenVPN

A recommended VPN tool is **OpenVPN**, that can be installed with this command:
```
sudo apt-get install openvpn
```

For using it we will need root permissions.
```
sudo openvpn <client.ovpn>
```

## ProtonVPN
Proton VPN is a privacy-focused VPN service developed by the team behind ProtonMail. It aims to provide secure internet access while preserving user anonymity.

**Key Features:**

- **Strong Security:** Uses AES-256 encryption and offers a no-logs policy.
- **Secure Core:** Routes traffic through privacy-friendly countries, enhancing anonymity.
- **Multi-Platform Support:** Available on Windows, macOS, Linux, Android, and iOS.
- **Free and Paid Plans:** Free tier with limited servers and speeds; paid plans offer more features and faster speeds ([Link](https://account.protonvpn.com/signup?plan=free&ref=faq
)). 

To obtain the OVPN file for using Proton VPN, you first need to create an account. Afterward, you can download it directly from their website.

Another way to use it is by installing the ProtonVPN application directly and connecting to the VPN through the app itself:

```bash
wget https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.4_all.deb

sudo dpkg -i ./protonvpn-stable-release_1.0.4_all.deb && sudo apt update

sudo apt install proton-vpn-gnome-desktop
```

Once installed, the application can be accessed via its GUI option.