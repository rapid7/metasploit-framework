
This module can be useful if you need to test the security of your server and your
website behind CloudFlare by discovering the real IP address.

More precisely, it is an simple "cloudflair" implementation for metasploit-framework.

## Verification Steps

  1. Install the module as usual
  2. Start msfconsole
  3. Do: `use auxiliary/gather/behind_cloudflare`
  4. Do: `set hostname www.zataz.com`
  5. Do: `run`

## Options

  **CENSYS_SECRET**

  Your Censys API SECRET.

  **CENSYS_UID**

  Your Censys API UID.

  **COMPSTR**

  You can use a custom string to perform the comparison. Default: TITLE or HOSTNAME if it's empty.
  The best way is always to use COMPSTR for a better result.

  **HOSTNAME**

  This is the hostname [fqdn] on which the website responds. But this can also be a domain.

    msf auxiliary(gather/behind_cloudflare) > set hostname www.zataz.com
    --or--
    msf auxiliary(gather/behind_cloudflare) > set hostname discordapp.com

  **Poxies**

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

  If successful, you must be able to obtain the IP(s) address of the website as follows:

  ```
msf auxiliary(gather/behind_cloudflare) > set verbose true 
verbose => true
msf auxiliary(gather/behind_cloudflare) > run

[*] Passive gathering information...
[*]  * ViewDNS.info: 36 IP address found(s).
[*]  * DNS Enumeration: 4 IP address found(s).
[*]  * Censys IPv4: 2 IP address found(s).
[*] 
[*] Clean cloudflare server(s)...
[+]  * TOTAL: 7 IP address found(s) after cleaning.
[*] 
[*] Bypass cloudflare is in progress...
[*]  * Trying: http://XXX.XXX.XXX.XXX:80/
      --> responded with an unexpected HTTP status code: 500
[*]  * Trying: https://XXX.XXX.XXX.XXX:443/
      --> responded with an unexpected HTTP status code: 500
[-] No direct-connect IP address found :-(
[*] Auxiliary module execution completed
  ```

  For example:

  For some reason you may need to change the URI path to interoperate with other than the index page.
  To do this specific thing:

  ```
  msf > use auxiliary/gather/behind_cloudflare
  msf auxiliary(gather/behind_cloudflare) > set HOSTNAME www.zataz.com
  hostname => www.zataz.com
  msf auxiliary(gather/behind_cloudflare) > set URIPATH /contacter/
  uripath => /contacter/
  msf auxiliary(gather/behind_cloudflare) > set compstr Contacter ZATAZ
  compstr => Contacter ZATAZ
  msf auxiliary(gather/behind_cloudflare) > run
  ...
  ```

## References

  1. <http://www.crimeflare.us:82/cfs.html#box>
  2. <https://github.com/HatBashBR>
  3. <https://github.com/christophetd/CloudFlair>
