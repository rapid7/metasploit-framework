# Dynamic DNS Update Injection

`dyn_dns_update` module allows adding or deleting DNS records
on a DNS server that allows unrestricted dynamic updates.

## Vulnerable Application

Any DNS server that allows dynamic update for none trusted source IPs.

## Verification Steps

 1. Start msfconsole
 2. Do: ```auxiliary/scanner/dns/dyn_dns_update```
 3. Do: ```set DOMAIN [IP]```
 4. Do: ```set NS [IP]```
 5. Do: ```set INJECTDOMAIN [IP]```
 6. Do: ```set INJECTIP [IP]```
 7. Do: ```set ACTION ADD```
 8. Do: ```run```

## Actions

There are two kind of actions the module can run:

 1. **ADD** - Add a new record. [Default]
 2. **DEL** - Delete an existing record.

## Targeting Information

WPAD may not work with Windows 2008+ targets due to a DNS block list: https://technet.microsoft.com/en-us/library/cc995261.aspx
