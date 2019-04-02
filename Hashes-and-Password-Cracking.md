# Intro

**WORK IN PROGRESS** - This page is a work in progress as the hashcat functionality is included in the metasploit framework, and as documentation is put together.  The information on this page may quickly become outdated, but can be used as a general guide.

This article will discuss the various libraries, dependencies, and functionality built in to metasploit for dealing with password hashes, and cracking them.  In general, this will not cover storing credentials in the database, which can be read about [here](https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners#the-scan-block).  Metasploit currently support cracking passwords with [John the Ripper](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/analyze) and (soon as of Apr 2, 2019) [hashcat](https://github.com/rapid7/metasploit-framework/pull/11671).

# Hashes

Many modules gather dump hashes from various software.  Anything from the OS: [Windows](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/hashdump.rb), [OSX](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/hashdump.rb), and [Linux](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/hashdump.rb), to applications such as [postgres](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/postgres/postgres_hashdump.rb), and [oracle](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/oracle/oracle_hashdump.rb).  Similar, to the [hash-identifier](https://code.google.com/archive/p/hash-identifier/) project, metasploit includes a library to identify the type of a hash in a standard way. [identify.rb](https://github.com/rapid7/metasploit-framework/blob/master/lib/metasploit/framework/hashes/identify.rb) can be given a hash, and will return the `jtr` type.  Metasploit standardizes to [John the Ripper](https://www.openwall.com/john/)'s types.  While you may know the hash type being dumped already, using this library will help standardize future changes.

## Hash Identify Example

In this first, simple, example we will simply show loading the library and calling its function.
```
require 'metasploit/framework/hashes/identify'
puts identify_hash "$1$28772684$iEwNOgGugqO9.bIz5sk8k/"
# note, bad hashes return an empty string since nil is not accepted when creating credentials in msf.
puts identify_hash "This_is a Fake Hash"
puts identify_hash "_9G..8147mpcfKT8g0U."
```
In practice, we receive the following output from this:
```
msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> require 'metasploit/framework/hashes/identify'
=> false
>> puts identify_hash "$1$28772684$iEwNOgGugqO9.bIz5sk8k/"
md5
=> nil
>> puts identify_hash "This_is a Fake Hash"

=> nil
>> puts identify_hash "_9G..8147mpcfKT8g0U."
des,bsdi,crypt
```

## Crackers

## Differences Between Hashcat vs JtR
This section will cover the differences between the two crackers.  This is not a comparison of speed, or why one may work better in a specific case than another.

### General Settings

| Description     | JtR              | hashcat             |
|-----------------|------------------|---------------------|
| session         | `--session`      | `--session`         |
| no logging      | `--nolog`        | `--logfile-disable` |
| config file     | `--config`       | (n/a)               |
| previous cracks | `--pot`          | `--potfile-path`    |
| type of hashes  | `--format`       | `--hash-type`       |
| wordlist        | `--wordlist`     | (last parameter)    |
| incremental     | `--incremental`  | `--increment`       |
| rules           | `--rules`        | `--rules-file`      |
| max run time    | `--max-run-time` | `--runtime`         |
| show results    | `--show`         | `--show`            |

### Hash Setting

| Hash              | JtR                     |  [hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes) |
|-------------------|-------------------------|--------------------|
| List formats      | `john --list=formats` `john --list=format-all-details` | `hashcat -h` |
| | | |
| des               | descrypt                | 1500               |
| md5 (crypt is $1$)| md5crypt                | 500                |
| sha1              |                         | 100                |
| bsdi              | bsdicrypt               | 12400              |
| sha256            | sha256crypt             | 7400               |
| sha512            | sha512crypt             | 1800               |
| blowfish          | bcrypt                  | 3200               |
| lanman            | lm                      | 3000               |
| NTLM              | nt                      | 1000               |
| mssql (05)        | mssql                   | 131                |
| mssql12           | mssql12                 | 1731               |
| mssql (2012/2014) | mssql05                 | 132                |
| oracle (10)       | oracle                  | 3100               |
| oracle 11         | oracle11                | 112                |
| oracle 12         | oracle12c               | 12300              |
| postgres          | dynamic_1034            | 12                 |
| mysql             | mysql                   | 200                |
| mysql-sha1        | mysql-sha1              | 300                |

While Metasploit standardizes with the JtR format, the hashcat [library](https://github.com/rapid7/metasploit-framework/blob/ed0b79721a388b33f11966491700f244e579ff53/lib/msf/core/auxiliary/hashcat.rb) includes the `jtr_format_to_hashcat_format` function to translate from jtr to hashcat.

### Example Hashes

Hashcat
* [hashcat.net](https://hashcat.net/wiki/doku.php?id=example_hashes)

JtR
* [pentestmonkey.net](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)
* [openwall.info](https://openwall.info/wiki/john/sample-hashes)

For testing Hashcat/JtR integration, this is a common list of commands to import example hashes of many different types.  When possible the username is separated by an underscore, and anything after it is the password.  For example `des_password`, the password for the hash is `password`:

```
creds add user:des_password hash:rEK1ecacw.7.c jtr:des
creds add user:md5_password hash:$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5
creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi
creds add user:sha256_password hash:$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256,crypt
creds add user:sha512_password hash:$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512,crypt
creds add user:blowfish_password hash:$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf
creds add user:lm_password ntlm:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C jtr:lm
creds add user:nt_password ntlm:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C jtr:nt
creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05
creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254 jtr:mssql
creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16 jtr:mssql12
creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql
creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1
## oracle (10) uses usernames in the hashing, so we can't overide that here
creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle
creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle
## oracle 11/12 H value, username is used
creds add user:DEMO hash:'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C' jtr:raw-sha1,oracle
## oracle 11/12 uses a LONG format, see lib/msf/core/auxiliary/jtr.rb
creds add user:oracle11_epsilon hash:'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C' jtr:raw-sha1,oracle
creds add user:oracle12c_epsilon hash:'H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B' jtr:pbkdf2,oracle12c
##postgres uses username, so we can't overide that here
creds add user:example postgres:md5be86a79bf2043622d58d5453c47d4860
```

This data breaks down to the following table:

| Hash Type | Username | Hash | Password | jtr format | Modules which dump this info | Modules which crack this | 
|-----------|----------|------|----------|------------|------------------------------|-------------------------|
| DES | des_password   |  `rEK1ecacw.7.c`                     | password | des  | | [auxiliary/analyze/jtr_aix](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_aix.rb) [auxiliary/analyze/jtr_linux](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_linux.rb) |
| MD5 | md5_password   | `$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/` | password | md5  | | [auxiliary/analyze/jtr_linux](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_linux.rb) |
| BSDi | bsdi_password | `_J9..K0AyUubDrfOgO4s`               | password | bsdi | | [auxiliary/analyze/jtr_linux](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_linux.rb) |
| SHA256 | sha256_password | `$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5` | password | sha256,crypt | | [auxiliary/analyze/jtr_linux](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_linux.rb) |
| SHA512 | sha512_password | `$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1` | password | sha512,crypt | | [auxiliary/analyze/jtr_linux](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_linux.rb) |
| Blowfish | blowfish_password | `$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe` | password | bf | | [auxiliary/analyze/jtr_linux](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_linux.rb) |
| Lanman | lm_password | `E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C` | password | lm | | [auxiliary/analyze/jtr_windows_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_windows_fast.rb) |
| NTLM | nt_password | `AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C` | password | nt | | [auxiliary/analyze/jtr_windows_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_windows_fast.rb) |
| MSSQL (2005) | mssql05_toto | `0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908` | toto | mssql05 | [auxiliary/scanner/mssql/mssql_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/mssql/mssql_hashdump.rb) | [auxiliary/analyze/jtr_mssql_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_mssql_fast.rb) |
| MSSQL | mssql_foo | `0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254` | foo | mssql | [auxiliary/scanner/mssql/mssql_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/mssql/mssql_hashdump.rb) | [auxiliary/analyze/jtr_mssql_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_mssql_fast.rb) |
| MSSQL (2012) | mssql12_Password1! | `0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16` | Password! | mssql12 | [auxiliary/scanner/mssql/mssql_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/mssql/mssql_hashdump.rb) | [auxiliary/analyze/jtr_mssql_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_mssql_fast.rb) |
| MySQL | mysql_probe | `445ff82636a7ba59` | probe | mysql | [auxiliary/scanner/mysql/mysql_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/mysql/mysql_hashdump.rb) | [auxiliary/analyze/jtr_mysql_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_mysql_fast.rb) |
| MySQL SHA1 | mysql-sha1_tere | `*5AD8F88516BD021DD43F171E2C785C69F8E54ADB` | tere | mysql-sha1 | [auxiliary/scanner/mysql/mysql_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/mysql/mysql_hashdump.rb) | [auxiliary/analyze/jtr_mysql_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_mysql_fast.rb) |
| Oracle | simon | `4F8BC1809CB2AF77` | A | des,oracle | [auxiliary/scanner/oracle/oracle_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/oracle/oracle_hashdump.rb) | [auxiliary/analyze/jtr_oracle_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_oracle_fast.rb) |
| Oracle | SYSTEM | `9EEDFA0AD26C6D52` | THALES | des,oracle | [auxiliary/scanner/oracle/oracle_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/oracle/oracle_hashdump.rb) | [auxiliary/analyze/jtr_oracle_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_oracle_fast.rb) |
| Oracle 11    | DEMO  | `S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C` | epsilon | raw-sha1,oracle | [auxiliary/scanner/oracle/oracle_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/oracle/oracle_hashdump.rb) | [auxiliary/analyze/jtr_oracle_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_oracle_fast.rb) |
| Oracle 11 | oracle11_epsilon | `S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C` | epsilon | raw-sha1,oracle | [modules/auxiliary/scanner/oracle/oracle_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/oracle/oracle_hashdump.rb) | [auxiliary/analyze/jtr_oracle_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_oracle_fast.rb) |
| Oracle 12 | oracle12_epsilon | `H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B` | epsilon | pbkdf2,oracle12c | [auxiliary/scanner/oracle/oracle_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/oracle/oracle_hashdump.rb) | [auxiliary/analyze/jtr_oracle_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_oracle_fast.rb) |
| Postgres | example | `md5be86a79bf2043622d58d5453c47d4860` | password | raw-md5,postgres | [auxiliary/scanner/postgres/postgres_hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/postgres/postgres_hashdump.rb) | [auxiliary/analyze/jtr_postgres_fast](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/jtr_postgres_fast.rb) |