## Vulnerable Application
[Syncovery For Linux with Web-GUI](https://www.syncovery.com/download/linux/)

This module attempts to brute-force valid login credentials for the Syncovery File Sync & Backup Software Web-GUI for Linux.
The default credentials are checked by default.

### Authors

- Jan Rude (mgm security partners GmbH)

### Platforms

- Unix

## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use modules/auxiliary/scanner/http/syncovery_linux_login`
4. Do: `set RHOSTS <TARGET HOSTS>`
5. Do: `run`
6. On success you should get valid credentials.

## Options

### USERNAME
Username used for login. Default is "default".

### PASSWORD
Password used for login. Default is "pass".

### TARGETURI
The path to Syncovery login.

### PORT
The (TCP) target port on which Syncovery is running. By default port 8999 is used for HTTP and port 8943 is used for HTTPS.

## Scenarios

### Syncovery for Linux with default credentials

```
msf6 > use modules/auxiliary/scanner/http/syncovery_linux_login
msf6 auxiliary(scanner/http/syncovery_linux_login) > set rhosts 192.168.178.26
rhosts => 192.168.178.26
msf6 auxiliary(scanner/http/syncovery_linux_login) > options

Module options (auxiliary/scanner/http/syncovery_linux_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD          pass             no        The password to Syncovery (default: pass)
   PASS_FILE                          no        File containing passwords, one per line
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            192.168.178.26   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             8999             yes       The target port (TCP)
   SSL               false            no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   true             yes       Stop guessing when a credential works for a host
   TARGETURI         /                no        The path to Syncovery
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME          default          yes       The username to Syncovery (default: default)
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts
   VHOST                              no        HTTP server virtual host

msf6 auxiliary(scanner/http/syncovery_linux_login) > run

[+] 192.168.178.26:8999 - Syncovery File Sync & Backup Software confirmed
[+] 192.168.178.26:8999 - Identified version: 9.48a
[+] 192.168.178.26:8999 - Success: 'default:pass'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
