> Notes copied and adapted from [Hacking Articles](https://www.hackingarticles.in/wireless-penetration-testing-wifite/).

**Wifite** is a great alternative to the more tedious to use wireless auditing tools and provides simple CLI to interact and perform wireless attacks. It has great features like 5GHz support, Pixie Dust attack, WPA/WPA2 handshake capture attack and PMKID attack as well.

## Basic Usage

We can launch this tool by simply typing the name of the tool. To view the help page we have a `-h`  flag.

![](https://1.bp.blogspot.com/-QE5s-Xwyais/YPKtZJENqiI/AAAAAAAAxhg/clcj7W-iYLU150NBlwvTpVu44N4I1J_6QCLcBGAsYHQ/s16000/1.png)


#### Initial Behavior

When Wifite is launched without arguments:

1. **Prompts to select a wireless interface**
    
    - The selected interface is automatically switched to **monitor mode**
        
2. **Scans nearby wireless networks**
    
    - Displays ESSID, channel, encryption, power, WPS status, and clients
        
3. **User interrupts scan (`CTRL + C`)**
    
4. **User selects target(s)**
    
5. **Wifite automatically launches all viable attacks** based on:
    
    - Encryption type
        
    - WPS availability
        
    - Client presence
        
    - AP capabilities
        

> Wifite follows an **attack chain**, not a single fixed attack.

#### Attack Decision Logic (Automatic)

Once a target is selected, Wifite evaluates:

```js
Identify encryption 
↓ 
Check WPS 
↓ 
Check PMKID support 
↓ 
Check client presence 
↓ 
Launch applicable attacks
```

Example for WPA/WPA2‑PSK:

1. PMKID attack
    
2. Handshake capture
    
3. Offline cracking (optional)

#### Possible Attacks Performed by Wifite

- **WEP ARP Replay Attack**: Exploits weak IV reuse in WEP by replaying ARP packets to generate enough encrypted traffic to statistically recover the WEP key.
- **WPA/WPA2 PMKID Attack**: Abuses APs that expose a PMKID in RSN frames, allowing offline password cracking without requiring a connected client.
- **WPA/WPA2 4‑Way Handshake Capture**: Captures the authentication handshake during client association, enabling offline dictionary or brute‑force attacks against the PSK.
- **WPS PIN Brute‑Force Attack**: Exploits the flawed WPS PIN validation process to recover the WPA/WPA2 passphrase directly from the access point.
- **WPS Pixie Dust Attack**: Targets weak WPS implementations with poor randomness, allowing offline recovery of the WPS PIN and associated PSK.
- **Deauthentication‑Assisted Handshake Capture**: Uses unauthenticated management frames to force client reconnection, increasing the chance of capturing a WPA/WPA2 handshake.
- **Offline Password Cracking**: Performs dictionary‑based cracking on captured handshakes or PMKID material without further interaction with the target network.
---

## ARP Replay Attack against WEP protocol

In this attack, the tool tries to listen for an ARP packet and sends it back to the access point. This way AP will be forced to create a new packet with new initialization vector (IV – starting variable to encrypt something). And now the tool would repeat the same process again till the time data is enough to crack the WEP key.

This can be done by:

```bash
wifite --wep
```

Then, `ctrl+c to stop scanning` and choose target. Here, 1: 

![](https://1.bp.blogspot.com/-zrUIjXQIdcg/YPK1Zn5RkLI/AAAAAAAAxiE/idXH-_lllAkwdBLQzpA_rNq4Gr_P20WdACLcBGAsYHQ/s16000/7.png)

As you can see that after 20 thousand plus replay packets, the tool has found the key successfully and saved it in a JSON file.

Please note that WPA **implements a sequence counter** to protect against replay attacks. Hence, it is recommended not to use WEP.


---

## WPA/WPA2 Handshake Capture

To execute this attack you need to execute the tool adding the `–skip-crack` option, which will stop the tool to crack any handshake that it captures.

```bash
wifite --skip-crack
```

![](https://1.bp.blogspot.com/-9YLZSqp5Tag/YPK1ee908ZI/AAAAAAAAxiM/V0YwTrY_wAspaena-1f3E9BAhmtsptowgCLcBGAsYHQ/s16000/8.png)

As you might have observed in the screenshot that the tool is automatically trying all the attacks against a specified target. Here, th specified target is  `1` for the AP `raaj` and you can see that it has tried for PMKID attack first, been unsuccessful and then launched handshake capture. This process will be the same for any target. The tool will automatically determine which attack works. Quite simple and hassle-free!

Here, we have successfully captured a handshake and saved it in a location: `/root/hs/<name>.cap`

Now, if we don’t use the skip-crack flag along with the command, the chain would look something like this:

```bash
wifite
```

Then, `ctrl+c to stop scanning` and choose target. Here, 1: 

![](https://1.bp.blogspot.com/-CIO9dURnnd4/YPK1k7az91I/AAAAAAAAxiU/qp5vU2I3WOcc1urGAcnCNXfe_vM14Y0jgCLcBGAsYHQ/s16000/9.png)

Chain:

- Identify APs
- Check protocol
- Attempt PMKID attack
- Attempt handshake attack
- If handshake found -> crack

And very evidently so, you can see that it has cracked the handshake file and given out the password as “**raj12345**”

It uses aircrack-ng’s dictionary attack module in the background.


---

## Some useful options

#### Filtering Attacks:

What if I want to skip out the PMKID step from the chain above? We can do this by:

```bash
wifite --no-pmkid
```

![](https://1.bp.blogspot.com/-SiMi6qVA3SY/YPK11-V4VoI/AAAAAAAAxik/JCCC70LXU8I_yeOfqht8tJUXRYBHIa41QCLcBGAsYHQ/s16000/10.png)

#### Scan Delay:

Another useful option is to give a scan time delay. This may be used in parallel to other options to evade security devices that have set a timeout for unauthenticated packets.

```bash
wifite -p 10
```

Here, the tool will put a delay of 10 seconds before attacking the targets.

**![](https://1.bp.blogspot.com/-PW-uJtmkGEk/YPK16sW_eYI/AAAAAAAAxio/T7ChD86Gxsg1sEJcUMw_Or76MAhN-lJMACLcBGAsYHQ/s16000/11.png)**

And now the tool is putting a delay of 10 seconds after every target

#### PMKID timeout:

This flag would enable us to set a timeout delay between each successful RSN packet request to the access point.

```bash
wifite --pmkid-timeout 130
```

![](https://1.bp.blogspot.com/-z2Ffvpbcod8/YPK1_KEzClI/AAAAAAAAxis/5APKWWAhYfQg6uLin_tXhg6ewQcmbKPQACLcBGAsYHQ/s16000/12.png)

Observe how there is a timeout of 130 seconds. I’ve been interrupted before 130 seconds by C TRL+C to stop the attack. Note how it says ”waiting for PMKID (1m 23s)”

![](https://1.bp.blogspot.com/-0KRJQdDEPuI/YPK2FNGG6OI/AAAAAAAAxiw/uezST4P4UJ0_RS3g94m9S8Ijxqtxb_sGwCLcBGAsYHQ/s16000/13.png)

#### Stop deauthentication on a particular ESSID:

This flag will stop the tool from conducting client deauthentication (often used in handshake captures). In a list of targets I want to stop preventing my tool to conduct deauthentication, this would yield useful

```bash
wifite -e raaj --nodeauths
```

- -e : ESSID (name of AP)

![](https://1.bp.blogspot.com/-sOMvD61ygj0/YPK2LEj7I9I/AAAAAAAAxi4/U-Q9UZLLC4AAm2-wpnDAaVEWlexXhPabACLcBGAsYHQ/s16000/14.png)

#### Targeting only WPA networks:

This flag helps us identify WPA only and attack the targets

```bash
wifite --wpa
```

![](https://1.bp.blogspot.com/-L9ZypAhPJY4/YPK2Vw6xbnI/AAAAAAAAxjA/We1uhtzvh5c1PwDmP9DISx3fSccun2gSACLcBGAsYHQ/s16000/15.png)

#### Ignore present handshakes:

Oftentimes we want a fresh start or our handshakes are just not behaving the way we want. For those times, we have a handy feature of ignoring the existing handshakes and capturing rather fresh or new ones.

```bash
wifite --new-hs
```

![](https://1.bp.blogspot.com/-vmWFIn0pYKo/YPK2ddwruaI/AAAAAAAAxjE/ntWJjHbGIXo5z3wswj0RlEkPbKbuK16yQCLcBGAsYHQ/s16000/16.png)

#### Supplying custom dictionary:

For our dictionary attacks, if we want to supply a custom wordlist we can do that within the tool’s interface too. This is done by the `dict` flag.

```bash
wifite --dict /root/dict.txt
```


**![](https://1.bp.blogspot.com/-LQ-6Ji1VQwU/YPK2lfzBwyI/AAAAAAAAxjM/VWTx5gwCp80XAAWNWsKS8YSMf64F-GTwACLcBGAsYHQ/s16000/17.png)**

Now, setting the target as above, we see that dictionary infact works

![](https://1.bp.blogspot.com/-oGfc6lKPrPY/YPK2rUrzCqI/AAAAAAAAxjQ/SEIEJcTUxgkpvEWOxQLrzQuQaAOVcNa-QCLcBGAsYHQ/s16000/18.png)

#### Display cracked APs:

To display a complete list of already cracked targets fetched from the tool’s database, we have the command:

```bash
wifite --cracked
```

![](https://1.bp.blogspot.com/-Q00nsMAOSAY/YPK2w0KPGkI/AAAAAAAAxjY/2JaxiMvXaPUTV5cYVxayR9_OTLM1HbZywCLcBGAsYHQ/s16000/19.png)

#### Killing conflicting processes:

This flag helps us kill all the jobs that may conflict with the working of the tool. It’s a great little cleanup technique before starting the tool.

```bash
wifite --kill
```

![](https://1.bp.blogspot.com/-ghWvQc8W6FA/YPK3OaVA3gI/AAAAAAAAxjo/L1S5Xa9njcoDGyjOKyQmq_zzzmWnyZz2gCLcBGAsYHQ/s16000/22.png)

#### MAC Spoofing:

MAC Address spoofing is a great technique to evade analyst’s vision and avoid getting caught by supplying the real MAC ID of your Wi-Fi adapter. First, we see our wifi card’s MAC ID by ifconfig

![](https://1.bp.blogspot.com/-4OAU0E848oQ/YPK3YjKqsHI/AAAAAAAAxj0/sK63RYbACbQUE4R0wDWeIVM40seFB_rPQCLcBGAsYHQ/s16000/24.png)

Note this MAC ID ends in **5C**. That’s all we need to visualize if MAC is being spoofed or not.

Now we spoof this MAC ID by wifite command:

```bash
wifite --random-mac
```

![](https://1.bp.blogspot.com/-2FH8NoNWRac/YPK3daYIo3I/AAAAAAAAxj4/GKV7XbxGgbsVM0vcwH-0-RAPubY-5TY1QCLcBGAsYHQ/s16000/25.png)

Observe how this new MAC ID ends in **09**. This means that spoofing has been done successfully and a random MAC has been put on the interface.

Now, after our job is done, this option will automatically reset the MAC ID too. Very efficient.

![](https://1.bp.blogspot.com/-DBwJj2CYJuE/YPK3h1c2vmI/AAAAAAAAxkA/WtISkIFsL8oyddu_IxrGK6BoOLZbq5pEQCLcBGAsYHQ/s16000/26.png)
