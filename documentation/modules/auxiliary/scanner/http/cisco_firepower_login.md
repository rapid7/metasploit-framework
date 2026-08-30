This module allows you to authenticate to Cisco Firepower Management console. The found credentials
could also be used in Cisco Firepower's SSH service, which would potentially give you remote code
execution.

## Vulnerable Application

The vulnerable software can be downloaded from Cisco as long as you are a member. Specifically,
this module was testing on version 6.0.1 during development.


For Cisco members, get the virtual appliance 6.0.1-2013 here:

https://software.cisco.com/download/release.html?mdfid=286259687&softwareid=286271056&release=6.0.1&flowid=54052


## Verification Steps

1. Make sure Cisco Firepower Management console's HTTPS service is running
2. Start ```msfconsole```
3. ```use auxiliary/scanner/http/cisco_firepower_login.rb```
4. ```set RHOSTS [IP]```
5. Set credentials
6. ```run```
7. You should see that the module is attempting to log in.

