## Introduction
This module uses the Shodan API to return all port information found on a given host IP.

#### NOTE:
In order for this module to function properly, a Shodan API key is needed. You can register for a free account here: https://account.shodan.io/register

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/shodan_host`
  3. Do: `set RHOSTS <targetip>`
  4. Do: `set SHODAN_APIKEY <your apikey>`
  5. Do: `run`
  6. If the execution is successful, the port opening status of the target server will be obtained

## Options

  **RHOSTS**

  The target machine(s) whose port information will be obtained from Shodan

  **SHODAN_APIKEY**

  This is the API key you receive when signing up for a Shodan account. It should be a 32 character string of random letters and numbers.

  **Proxies**
  A proxy chain of format type:host:port[,type:host:port][...] that will be used to establish the connection to the Shodan servers.


## Scenarios

### Single IP
Running the module against a real system (in this case, the Google DNS server):

```
msf6 > use auxiliary/gather/shodan_host
msf6 auxiliary(gather/shodan_host) > show options

Module options (auxiliary/gather/shodan_host):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   SHODAN_APIKEY                   yes       The SHODAN API key

msf6 auxiliary(gather/shodan_host) > set RHOSTS 8.8.8.8
RHOSTS => 8.8.8.8
msf6 auxiliary(gather/shodan_host) > set SHODAN_APIKEY *redacted*
SHODAN_APIKEY => *redacted*
msf6 auxiliary(gather/shodan_host) > run
[*] Running module against 8.8.8.8

[+] 8.8.8.8:53
[*] Auxiliary module execution completed
msf6 auxiliary(gather/shodan_host) >
```

### Domain Name

```
msf6 > use auxiliary/gather/shodan_host
msf6 auxiliary(gather/shodan_host) > show options

Module options (auxiliary/gather/shodan_host):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   SHODAN_APIKEY                   yes       The SHODAN API key

msf6 auxiliary(gather/shodan_host) > set RHOSTS www.google.com
RHOSTS => www.google.com
msf6 auxiliary(gather/shodan_host) > set SHODAN_APIKEY *redacted*
SHODAN_APIKEY => *redacted*
msf6 auxiliary(gather/shodan_host) > run
[*] Running module against 172.217.12.36

[+] 172.217.12.36:80
[+] 172.217.12.36:443
[*] Running module against 2607:f8b0:4000:815::2004
[-] The target IP address has not been scanned by Shodan!
[*] Auxiliary module execution completed
msf6 auxiliary(gather/shodan_host) >
```