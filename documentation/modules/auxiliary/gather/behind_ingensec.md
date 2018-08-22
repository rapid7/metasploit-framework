
This module can be useful if you need to test the security of your server and your
website behind BinarySec/IngenSec by discovering the real IP address.

More precisely, I use multiple data sources (DNS enumeration, SEO PrePost) to collect
assigned (or have been) IP addresses from the targeted site or domain that uses the 
BinarySec or IngenSec WAF as a service.

After a cleaning step, ie. if the IP addresses come from the servers of BinarySec or
IngenSec. The module runs tests to discover the true address behind the WAF.

This French security solution is (apparently) mainly deployed on the Reunion island.

## Verification Steps

  1. Install the module as usual
  2. Start msfconsole
  3. Do: `use auxiliary/gather/behind_ingensec`
  4. Do: `set hostname www.ingensec.com`
  5. Do: `run`

## Options

  **HOSTNAME**

  This is the hostname [fqdn] on which the website responds. But this can also be a domain.

    msf auxiliary(gather/behind_ingensec) > set hostname www.ingensec.com
    --or--
    msf auxiliary(gather/behind_ingensec) > set hostname ingensec.com

  **RPORT**

  The target TCP port on which the protected website responds. Default: 443

  **SSL**

  Negotiate SSL/TLS for outgoing connections. Default: true

  **URIPATH**

  The URI path on which to perform the page comparison. Default: '/'

  **Poxies**

  A proxy chain of format type:host:port[,type:host:port][...]. It's optional.

  **THREADS**

  Number of concurent threads needed for DNS enumeration. Default: 15

  **WORDLIST**

  Name list required for DNS enumeration. Default: ~/metasploit-framework/data/wordlists/namelist.txt

## Advanced options

  **VERBOSE**

  You can also enable the verbose mode to have more information displayed in the console.

## Scenarios

### For auditing purpose

  If successful, you must be able to obtain the IP address of the website as follows:

  ```
  [*] Passive gathering information...
  [*]  * PrePost SEO: 1 IP address found(s).
  [*]  * DNS Enumeration: 12 IP address found(s).
  [*] 
  [*] Clean binarysec/ingensec server(s)...
  [+]  * TOTAL: 3 IP address found(s) after cleaning.
  [*] 
  [*] Bypass BinarySec/IngenSec is in progress...
  [*]  * Initial request to the original server for comparison
  [*]  * Trying: 41.213.137.67
  [+] A direct-connect IP address was found: 41.213.137.67
  [*] Auxiliary module execution completed
  ```

  For example:

  For some reason you may need to change the URI path to interoperate with other than the index page.
  To do this specific thing:

  ```
  msf > use auxiliary/gather/behind_ingensec
  msf auxiliary(gather/behind_ingensec) > set HOSTNAME www.ingensec.com
  hostname => www.ingensec.com
  msf auxiliary(gather/behind_ingensec) > set URIPATH /fct_securite.html
  uripath => /fct_securite.html
  msf auxiliary(gather/behind_ingensec) > run
  ...
  ```

## TOTO list

  1. Add other data sources (censys, ...)
  2. Add customized DNS resolver
  3. Add customized string comparison

## References

  1. <https://reunion.orange.fr/actu/reunion/binarysec-une-start-up-reunionnaise-tres-surveillee.html>
  2. <https://www.ovh.com/fr/marketplace/partner/ingen-security.xml>
