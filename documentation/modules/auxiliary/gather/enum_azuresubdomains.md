## Introduction
Microsoft makes use of a number of different domains and subdomains for each of their Azure services. From SQL 
databases to SharePoint drives, each service maps to its respective domain/subdomain, and these can be identified 
through DNS enumeration to yield information about the target domain's infrastructure. 
```enum_azuresubdomains.rb``` is a Metasploit module for enumerating public Azure services by validating 
legitimate subdomains through various DNS record queries. This cloud reconnaissance module identifies API 
services, storage accounts, key vaults, and databases.

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/enum_azuresubdomains`
  3. Do: `set DOMAIN <Target Domain>`
  5. Do: `run`

## Options

  **DOMAIN**

  The target domain to enumerate without the Top Level Domain (Example: victim.org would just be victim). 

  **PERMUTATIONS**

  This appends and prepends permutated keywords to identify common domain name variations.


## Scenarios

Running the module against a real system (in this case, the University of Maryland's online Azure services):

```
msf6 > use auxiliary/gather/enum_azuresubdomains
msf6 auxiliary(gather/enum_azuresubdomains) > show options 

Module options (auxiliary/gather/enum_azuresubdomains):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DOMAIN                         yes       The target domain without TLD (Ex: victim rather than victim.org)
   ENUM_A        true             yes       Enumerate DNS A record
   ENUM_CNAME    true             yes       Enumerate DNS CNAME record
   ENUM_MX       true             yes       Enumerate DNS MX record
   ENUM_NS       true             yes       Enumerate DNS NS record
   ENUM_SOA      true             yes       Enumerate DNS SOA record
   ENUM_TXT      true             yes       Enumerate DNS TXT record
   NS                             no        Specify the nameservers to use for queries, space separated
   PERMUTATIONS  false            no        Prepend and append permutated keywords to domain (This option can 
take minutes to complete)
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RPORT         53               yes       The target port (TCP)
   SEARCHLIST                     no        DNS domain search list, comma separated
   THREADS       1                yes       Number of threads to use in threaded queries


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/enum_azuresubdomains) > set DOMAIN umuc365
DOMAIN => umuc365
msf6 auxiliary(gather/enum_azuresubdomains) > set PERMUTATIONS true 
PERMUTATIONS => true
msf6 auxiliary(gather/enum_azuresubdomains) > run

[*] Discovered Target Domain: umuc365.mail.protection.outlook.com 

[*] Querying DNS CNAME records for umuc365.mail.protection.outlook.com
[*] Querying DNS NS records for umuc365.mail.protection.outlook.com
[*] Querying DNS MX records for umuc365.mail.protection.outlook.com
[*] Querying DNS SOA records for umuc365.mail.protection.outlook.com
[*] Querying DNS TXT records for umuc365.mail.protection.outlook.com

[*] Discovered Target Domain: umuc365.sharepoint.com 

[*] Querying DNS CNAME records for umuc365.sharepoint.com
[+] umuc365.sharepoint.com CNAME: 2732-ipv4v6e.clump.dprodmgd105.aa-rt.sharepoint.com
[*] Querying DNS NS records for umuc365.sharepoint.com
[*] Querying DNS MX records for umuc365.sharepoint.com
[*] Querying DNS SOA records for umuc365.sharepoint.com
[*] Querying DNS TXT records for umuc365.sharepoint.com

[*] Discovered Target Domain: umuc365-web.sharepoint.com 

[*] Querying DNS CNAME records for umuc365-web.sharepoint.com
[+] umuc365-web.sharepoint.com CNAME: umuc365.sharepoint.com
[*] Querying DNS NS records for umuc365-web.sharepoint.com
[*] Querying DNS MX records for umuc365-web.sharepoint.com
[*] Querying DNS SOA records for umuc365-web.sharepoint.com
[*] Querying DNS TXT records for umuc365-web.sharepoint.com
[*] Auxiliary module execution completed
  ```
