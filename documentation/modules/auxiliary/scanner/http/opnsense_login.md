## Vulnerable Application

This module attempts to bruteforce credentials for OPNSense.

This module was specifically tested on version 25.1 and 21.1, with older versions being unavailable from OPNSense mirrors.

Note:

By default, OPNSense comes with a built-in account named `root` with the password being `opnsense`.

When performing too many login attempts, OPNSense will drop all packets coming from your IP, until the router is either:
- Restarted
- An anti-lockout rule is added

## Verification Steps

1. Set up an OPNSense VM or target a real installation
1. Start `bundle exec ./msfconsole -q`
1. `use auxiliary/scanner/http/opnsense_login`
1. `set ssl true`
1. `set pass_file ...`
1. `set user_file ...`
1. `run`
1. or, using some example inline options:
```
run pass_file=data/wordlists/default_pass_for_services_unhash.txt \
 user_file=data/wordlists/default_pass_for_services_unhash.txt \ 
 STOP_ON_SUCCESS=true SSL=true rport=443
```
1. Verify you get a login:
```
[+] 192.168.207.158:443 - Login Successful: root:opnsense
```

## Options

### BLANK_PASSWORD

Set to `true` if an additional login attempt should be made with an empty password for every user.

### BRUTEFORCE_SPEED

How fast to bruteforce, from 0 to 5

### PASSWORD

A specific password to authenticate with

### PASS_FILE

File containing passwords, one per line

### STOP_ON_SUCCESS

Stop guessing when a credential works for a host

### THREADS

The number of concurrent threads (max one per host)

### USERPASS_FILE

File containing users and passwords separated by space, one pair per line

### USER_FILE

File containing usernames, one per line

### VERBOSE

Whether to print output for all attempts

## Scenarios
```
msf6 auxiliary(scanner/http/opnsense_login) > options

Module options (auxiliary/scanner/http/opnsense_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ANONYMOUS_LOGIN   false            yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD          opnsense         no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            192.168.207.161  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             443              yes       The target port (TCP)
   SSL               true             yes       Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   TARGETURI         /                yes       The base path to the OPNSense application
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME          root             no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts
   VHOST                              no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/http/opnsense_login) > run
[+] 192.168.207.161:443 - Login Successful: root:opnsense
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
