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

| Hash              | JtR john --list=formats |  [hashcathashcat -h](https://hashcat.net/wiki/doku.php?id=example_hashes) |
|-------------------|-------------------------|--------------------|
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