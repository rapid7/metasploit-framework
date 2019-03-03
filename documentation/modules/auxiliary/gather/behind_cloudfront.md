
This module can be useful if you need to test the security of your server and your
website behind Amazon CloudFront by discovering the real IP address.

More precisely, I use multiple data sources (DNS enumeration, ViewDNS.info) to collect
assigned (or have been) IP addresses from the targeted site or domain that uses the 
Amazon CloudFront CDN.

After a cleaning step, ie. if the IP addresses come from the servers of Amazon
CloudFront. The module runs tests to discover the true address behind the CDN.

## Verification Steps

  1. Install the module as usual
  2. Start msfconsole
  3. Do: `use auxiliary/gather/behind_cloudfront`
  4. Do: `set hostname www.xxxxxxxx.com`
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

    msf auxiliary(gather/behind_cloudfront) > set hostname www.xxxxxxxx.com
    --or--
    msf auxiliary(gather/behind_cloudfront) > set hostname xxxxxxxx.com

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
msf auxiliary(gather/behind_cloudfront) > run

[*] Passive gathering information...
[*]  * ViewDNS.info: 1 IP address found(s).
[*]  * DNS Enumeration: 45 IP address found(s).
[*] Clean cloudfront server(s)...
[+]  * TOTAL: 15 IP address found(s) after cleaning.
[*] 
[*] Bypass cloudfront is in progress...
[*]  * Initial request to the original server for comparison
[*]  * Trying: http://XXX.XX.XXX.XX:80/
[*]  * Trying: http://XXX.XX.XXX.XX:80/
[*]  * Trying: http://XXX.XX.XXX.X:80/
      --> responded with an unexpected HTTP status code: 301
[*]  * Trying: https://XXX.XX.XXX.X:443/
      --> responded with an unexpected HTTP status code: 301
[*]  * Trying: http://XXX.XX.XXX.XX:80/
[*]  * Trying: http://XX.XXX.XX.XXX:80/
      --> responded with an unexpected HTTP status code: 301
[*]  * Trying: https://XX.XXX.XX.XXX:443/
      --> responded with an unexpected HTTP status code: 301
[*]  * Trying: http://XX.XXX.XX.XX:80/
      --> responded with an unexpected HTTP status code: 503
[*]  * Trying: https://XX.XXX.XX.XX:443/
      --> responded with an unexpected HTTP status code: 404
[*]  * Trying: http://XXX.XX.XX.XX:80/
[*]  * Trying: https://XXX.XX.XX.XX:443/
[*]  * Trying: https://XXX.XX.XXX.XX:443/
[*]  * Trying: http://XX.XX.XXX.XXX:80/
      --> responded with an unexpected HTTP status code: 301
[*]  * Trying: https://XX.XX.XXX.XXX:443/
[+] A direct-connect IP address was found: https://XX.XX.XXX.XXX:443/
[*]  * Trying: http://XX.XXX.XXX.XXX:80/
[*]  * Trying: https://XX.XXX.XXX.XXX:443/
[*]  * Trying: http://XX.XX.XX.XX:80/
      --> responded with an unexpected HTTP status code: 502
[*]  * Trying: https://XX.XX.XX.XX:443/
      --> responded with an unexpected HTTP status code: 502
[*] Auxiliary module execution completed
  ```

  For example:

  For some reason you may need to change the URI path to interoperate with other than the index page.
  To do this specific thing:

  ```
  msf > use auxiliary/gather/behind_cloudfront
  msf auxiliary(gather/behind_cloudfront) > set HOSTNAME www.xxxxxxxx.com
  hostname => www.xxxxxxxx.com
  msf auxiliary(gather/behind_cloudfront) > set URIPATH /about.html
  uripath => /about.html
  msf auxiliary(gather/behind_cloudfront) > run
  ...
  ```

## References

  1. <https://aws.amazon.com/fr/cloudfront/>
  2. <https://github.com/mekhalleh/behind_cloudflare>
