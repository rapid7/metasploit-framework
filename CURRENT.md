Active Metasploit 5 development will sometimes push aggressive changes.
Integrations with 3rd-party tools, as well as general usage, may change quickly
from day to day. Some of the steps for dealing with major changes will be
documented here. We will continue to maintain the Metasploit 4.x branch until
Metasploit 5.0 is released.

**2018/01/17 - [internal] module cache reworked to not store metadata in PostgreSQL**

Metasploit no longer stores module metadata in a PostgreSQL database, instead
storing it in a cache file in your local ~/.msf4 config directory. This has a
number of advantages:

 * Fast searches whether you have the database enabled or not (no more slow search mode)
 * Faster load time for msfconsole, the cache loads more quickly
 * Private module data is not uploaded to a shared database, no collisions
 * Adding or deleting modules no longer displays file-not-found error messages on start in msfconsole
 * Reduced memory consumption

Code that reads directly from the Metasploit database for module data will need
to use the new module search API.
