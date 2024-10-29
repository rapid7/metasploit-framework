## Vulnerable Application

  This post-exploitation module is to attack Active Directory integration solutions on UNIX. Specifically, it
  obtains all Kerberos tickets on the targeted UNIX machine.

  More detail about the underlying research from which these modules were derived can be found at:
  
  * https://labs.portcullis.co.uk/blog/an-offensive-introduction-to-active-directory-on-unix/

  This post contains both links to the Black Hat Europe 2018 presentation where the research was publicly
  disclosed as well as the Portcullis Labs GitHub repo from which this post-exploitation module is derived.

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Establish a valid Meterpreter session
  4. Do: ```use post/multi/gather/unix_kerberos_tickets```
  5. Do: ```run```
  6. You should get the Kerberos tickets

  Files will be retrieved and placed into the Metasploit loot sub-system as unix_kerberos_tickets_*.

  There are no CVEs aligned to these post-exploitation modules because no specific vulnerabilities are being
  exploited in gathering these files. The post-exploitation module is intended to operate on sessions where
  root (or appropriate user) privileges has already been obtained.

## Scenarios

### SSS (sssd)

  On a system running SSS (sssd), the modules will gather:

  * /var/lib/sss/db/ccache_*
  * Files matching the default_ccache_name property in /etc/krb5.conf (usually /tmp/krb5*)

### One Identity Vintela Authentication Services (vasd)

  On a system running One Identity's Vintela Authentication Services (vasd), the modules will gather:

  * /tmp/krb5*
