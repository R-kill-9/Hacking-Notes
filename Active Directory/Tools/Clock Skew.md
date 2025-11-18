Kerberos authentication requires the client and Domain Controller (DC) to have closely synchronized clocks.  

By default, the allowed difference is ±5 minutes.

- **Error Message:**

```bash
Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)
```

This means your system time is too far off compared to the DC’s time.


---

## How to Fix Clock Skew

- Useing `rdate`:

```bash
sudo rdate -n <dc_ip>
```

- Using `ntpdate`:

```bash
sudo ntpdate -u <dc_ip>
```


- Using `fixtime.py`

Script available here: [ADUtilities FixTime](https://github.com/5epi0l/ADUtilities/tree/main/FixTime)

```bash
python3 fixtime.py -u http://10.10.11.95
```
