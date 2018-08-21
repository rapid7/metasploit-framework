
This module can be useful if you need to test the security of your server and your
website behind CloudFlare by discovering the real IP address.

More precisely, it is an "hatcloud" implementation for metasploit-framework. With the
difference that this module operates the verification itself because the Crimeflare databases
does not seem up to date.

## Verification Steps

  1. Install the module as usual
  2. Start msfconsole
  3. Do: `use auxiliary/gather/behind_cloudflare`
  4. Do: `set hostname www.zataz.com`
  5. Do: `run`

## Options

  **HOSTNAME**

  This is the hostname [fqdn] on which the website responds. But this can also be a domain.

    msf auxiliary(gather/behind_cloudflare) > set hostname www.zataz.com
    --or--
    msf auxiliary(gather/behind_cloudflare) > set hostname discordapp.com

  **RPORT**

  The target TCP port on which the protected website responds. Default: 443

  **SSL**

  Negotiate SSL/TLS for outgoing connections. Default: true

  **URIPATH**

  The URI path on which to perform the page comparison. Default: '/'

  **Poxies**

  A proxy chain of format type:host:port[,type:host:port][...]. It's optional.

## Advanced options

  **VERBOSE**

  You can also enable the verbose mode to have more information displayed in the console.

## Scenarios

### For auditing purpose

  If successful, you must be able to obtain the IP address of the website as follows:

  ```
  [*] Previous lookups from Crimeflare...
  [*]  * 2018-08-20 | XXX.XXX.XXX.XXX
  [*] 
  [*] Bypass Cloudflare is in progress...
  [*]  * Initial request to the original server for comparison
  [+] A direct-connect IP address was found: XXX.XXX.XXX.XXX
  [*] Auxiliary module execution completed
  ```

  For example:

  For some reason you may need to change the URI path to interoperate with other than the index page.
  To do this specific thing:

  ```
  msf > use auxiliary/gather/behind_cloudflare
  msf auxiliary(gather/behind_cloudflare) > set HOSTNAME www.zataz.com
  hostname => adopteunartiste.com
  msf auxiliary(gather/behind_cloudflare) > set URIPATH /contacter/
  uripath => /contacter/
  msf auxiliary(gather/behind_cloudflare) > run
  ...
  ```

## TOTO list

  1. Add other data sources (enumeration DNS, censys, ...)

## References

  1. <http://www.crimeflare.us:82/cfs.html#box>
  2. <https://github.com/HatBashBR>

