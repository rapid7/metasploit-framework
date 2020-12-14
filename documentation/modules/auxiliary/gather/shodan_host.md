## Introduction
This module uses the shodan API to return all port information found on a given host IP.

#### NOTE:
In order for this module to function properly, a Shodan API key is needed. You can register for a free account here: https://account.shodan.io/register

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/shodan_host`
  3. Do: `set TARGET <targetip>`
  4. Do: `set SHODAN_APIKEY <your apikey>`
  5. Do: `run`
  6. If the execution is successful, the port opening status of the target server will be obtained

## Options

  **TARGET**

  The target host whose port information needs to be obtained

  **SHODAN_APIKEY**

  This is the API key you receive when signing up for a Shodan account. It should be a 32 character string of random letters and numbers.


## Scenarios

Running the module against a real system (in this case, the Google DNS server):

  ```
msf5 > use auxiliary/gather/shodan_host 
msf5 auxiliary(gather/shodan_host) > show options 

Module options (auxiliary/gather/shodan_host):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          80               yes       The target port (TCP)
   SHODAN_APIKEY                   yes       The SHODAN API key
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                           no        HTTP server virtual host

msf5 auxiliary(gather/shodan_host) > set RHOSTS 8.8.8.8
RHOSTS => 8.8.8.8
msf5 auxiliary(gather/shodan_host) > set SHODAN_APIKEY [redacted]
SHODAN_APIKEY => [redacted]
msf5 auxiliary(gather/shodan_host) > run
[*] Running module against 8.8.8.8

[+] 8.8.8.8:53
[*] Auxiliary module execution completed
  ```
