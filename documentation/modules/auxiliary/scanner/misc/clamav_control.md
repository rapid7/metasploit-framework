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
```

You might also need to add the following to /etc/clamav/clamd.conf:

```
# TCP port address.
# Default: no
TCPSocket 3310

# TCP address.
# By default we bind to INADDR_ANY, probably not wise.
# Enable the following to provide some degree of protection
# from the outside world.
# Default: no
TCPAddr 0.0.0.0

# Maximum length the queue of pending connections may grow to.
# Default: 15
MaxConnectionQueueLength 30

# Clamd uses FTP-like protocol to receive data from remote clients.
# If you are using clamav-milter to balance load between remote clamd daemons
# on firewall servers you may need to tune the options below.

# Close the connection when the data size limit is exceeded.
# The value should match your MTA's limit for a maximum attachment size.
# Default: 10M
StreamMaxLength 55M

# Limit port range.
# Default: 1024
#StreamMinPort 30000
# Default: 2048
#StreamMaxPort 32000

# Maximum number of threads running at the same time.
# Default: 10
MaxThreads 50

# Waiting for data from a client socket will timeout after this time (seconds).
# Value of 0 disables the timeout.
# Default: 120
ReadTimeout 300

# Waiting for a new job will timeout after this time (seconds).
# Default: 30
#IdleTimeout 60

# Maximum depth directories are scanned at.
# Default: 15
#MaxDirectoryRecursion 20
```

And finally, start the service:

```
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