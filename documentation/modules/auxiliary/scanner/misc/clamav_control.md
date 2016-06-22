ClamAV is an open source antivirus engine for detecting trojans, viruses, malare, and other
malicious threats.

clamav_control takes advantage of a possible misconfiguration in the ClamAV service on release
0.99.2 if the service is tied to a socket, and allows you fingerprint the version, and being
able to shut down the service.

## Vulnerable Application

To install ClamAV from Ubuntu:

```
$ sudo apt-get install clamav clamav-daemon
$ sudo freshclam
$ sudo /etc/init.d/clamav-daemon start
```

## Options

clamav_control comes with two actions:

**VERSION**

This is the default action, and shows you the ClamAV version. Output example:

```
msf auxiliary(clamav_control) > run

[+] 192.168.1.203:3310    - ClamAV 0.98.7/21772/Wed Jun 22 12:54:15 2016
```

**SHUTDOWN**

This action allows you to shutdown ClamAV. You can also use the VERSION action again to verify
whether is service is down or not.