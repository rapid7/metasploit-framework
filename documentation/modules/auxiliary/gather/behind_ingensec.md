
This module can be useful if you need to test the security of your server and your
website behind BinarySec/IngenSec by discovering the real IP address.

More precisely, I use multiple data sources (DNS enumeration, ViewDNS.info) to collect
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

  **CENSYS_SECRET**

  Your Censys API SECRET.

  **CENSYS_UID**

  Your Censys API UID.

  **COMPSTR**

  You can use a custom string to perform the comparison. Default: TITLE if it's empty.
  The best way is always to use COMPSTR for a better result.

  **HOSTNAME**

  This is the hostname [fqdn] on which the website responds. But this can also be a domain.

    msf auxiliary(gather/behind_ingensec) > set hostname www.ingensec.com
    --or--
    msf auxiliary(gather/behind_ingensec) > set hostname ingensec.com

  **Proxies**

  A proxy chain of format type:host:port[,type:host:port][...]. It's optional.

  **RPORT**

  The target TCP port on which the protected website responds. Default: 443

  **SSL**

  Negotiate SSL/TLS for outgoing connections. Default: true

  **THREADS**

  Number of concurent threads needed for DNS enumeration. Default: 8

  **URIPATH**

  The URI path on which to perform the page comparison. Default: '/'

  **WORDLIST**

  Name list required for DNS enumeration. Default: ~/metasploit-framework/data/wordlists/namelist.txt

## Advanced options

  **DNSENUM**

  Set DNS enumeration as optional. Default: true

  **NS**

  Specify the nameserver to use for queries. Default: is system DNS

  **TIMEOUT**

  HTTP(s) request timeout. Default: 15

  **VERBOSE**

  You can also enable the verbose mode to have more information displayed in the console.

## Scenarios

### For auditing purpose

  If successful, you must be able to obtain the IP address of the website as follows:

  ```
[*] Passive gathering information...
[*]  * ViewDNS.info: 1 IP address found(s).
[*]  * DNS Enumeration: 17 IP address found(s).
[*]  * Censys IPv4: 0 IP address found(s).
[*] 
[*] Clean binarysec/ingensec server(s)...
[+]  * TOTAL: 5 IP address found(s) after cleaning.
[*] 
[*] Bypass BinarySec/IngenSec is in progress...
[*]  * Initial request to the original server for comparison
[*]  * Trying: http://87.98.168.187:80/
[*]  * Trying: https://87.98.168.187:443/
[*]  * Trying: http://87.98.172.199:80/
[*]  * Trying: http://87.98.159.4:80/
      --> responded with an unexpected HTTP status code: 301
[*]  * Trying: https://87.98.159.4:443/
[-] No direct-connect IP address found :-(
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

  You can also run this script and take the results in the notes.

  ```
  use auxiliary/gather/behind_ingensec

  <ruby>
  File.open('/tmp/ingensec_hosts.lst', 'r') do | file |
    file.each_line do | hostname |
      run_single("set HOSTNAME #{hostname}")
      run_single('run')

      # run_single("set RPORT 80")
      # run_single("set SSL false")
      # run_single('run')
    end
  end
  </ruby>
  ```

  ```
  msf > resource /tmp/auto_discover_ingensec.rc
  [*] Processing /tmp/auto_discover_ingensec.rc for ERB directives.
  resource (/tmp/auto_discover_ingensec.rc)> use auxiliary/gather/behind_ingensec
  [*] resource (/tmp/auto_discover_ingensec.rc)> Ruby Code (248 bytes)
  ...
  ...
  msf auxiliary(gather/behind_ingensec) > notes 
  [*] Time: 2018-08-23 12:27:35 UTC Note: host=XXX.XXX.XXX.XXX type=behind_ingensec data={"vhost"=>"www.xxxxxxx.com", "real_ip"=>"XXX.XXX.XXX.XXX", "sname"=>"http"}
  [*] Time: 2018-08-23 12:27:35 UTC Note: host=XXX.XXX.XXX.XXX type=behind_ingensec data={"vhost"=>"www.xxxxxxx.com", "real_ip"=>"XXX.XXX.XXX.XXX", "sname"=>"https"}
  ```

## References

  1. <https://reunion.orange.fr/actu/reunion/binarysec-une-start-up-reunionnaise-tres-surveillee.html>
  2. <https://www.ovh.com/fr/marketplace/partner/ingen-security.xml>
