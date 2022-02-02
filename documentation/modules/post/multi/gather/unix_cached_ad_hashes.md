## Vulnerable Application

  This post-exploitation module is to attack Active Directory integration solutions on UNIX. Specifically, it
  obtains all cached AD hashes on the targeted UNIX machine. These can be cracked with John the Ripper (JtR).

  More detail about the underlying research from which these modules were derived can be found at:
  
  * https://labs.portcullis.co.uk/blog/an-offensive-introduction-to-active-directory-on-unix/

  This post contains both links to the Black Hat Europe 2018 presentation where the research was publicly
  disclosed as well as the Portcullis Labs GitHub repo from which this post-exploitation module is derived.

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Establish a valid Meterpreter session
  4. Do: ```use post/multi/gather/unix_cached_ad_hashes```
  5. Do: ```run```
  6. You should get the cached hashes
  7. Additional tools need to be run to extract the hashes in a crackable format

  Files will be retrieved and placed into the Metasploit loot sub-system as unix_cached_ad_hashes_*.

  There are no CVEs aligned to these post-exploitation modules because no specific vulnerabilities are being
  exploited in gathering these files. The post-exploitation module is intended to operate on sessions where
  root (or appropriate user) privileges has already been obtained.

## Scenarios

### Samba (smbd)
  
  On a system running Samba (smbd), the modules will gather:

  * /var/lib/samba/private/secrets.tdb
  * /var/lib/samba/passdb.tdb

  Use tdbdump to extract structed data from these files (`tdbdump #{filename}`), and search for the phrase
  `cachedPassword`. The hash should be in the same format as hashes in /etc/shadow (e.g. `$6$...`).

  JtR can natively crack these hashes.

### SSS (sssd)

  On a system running SSS (sssd), the modules will gather:

  * /var/lib/sss/db/cache_*

  Use tdbdump to extract structed data from these files (`tdbdump #{filename}`), and search for the phrase
  `cachedPassword`. The hash should be in the same format as hashes in /etc/shadow (e.g. `$6$...`).

  JtR can natively crack these hashes.

### One Identity Vintela Authentication Services (vasd)

  On a system running One Identity's Vintela Authentication Services (vasd), the modules will gather:

  * /var/opt/quest/vas/authcache/vas_auth.vdb

  JtR can crack the cached hashes extracted from this database using sqlite3 using the dynamic.conf rules located
  in our GitHub repo:

  * https://github.com/portcullislabs/linikatz/tree/master/red/JohnTheRipper
