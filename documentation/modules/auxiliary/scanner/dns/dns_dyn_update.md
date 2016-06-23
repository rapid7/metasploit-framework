# Dynamic DNS Update Injection
`dyn_dns_update` module allows adding and/or deleting an '**A**' record to
any remote DNS server that allows unrestricted dynamic updates.

## Vulnerable Application
Any DNS server that allows dynamic update for none trusted source IPs.

## Verification Steps
1. Start msfconsole
2. Do: ```auxiliary/scanner/dns/dyn_dns_update```
3. Do: ```set DOMAIN [IP]```
3. Do: ```set NS [IP]```
3. Do: ```set INJECTDOMAIN [IP]```
3. Do: ```set INJECTIP [IP]```
3. Do: ```set ACTION ADD```
6. Do: ```run```

## Actions
There are tow kind of actions the module can ran:
1. **ADD** - Add a new record. [Default]
2. **DEL** - Delete an existing record.
