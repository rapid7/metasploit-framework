## Vulnerable Application

This module attempts to authenticate to an AppleTV service with the username, 'AirPlay'.
The device has two different access control modes: OnScreen and Password.
The difference between the two is the password in OnScreen mode is numeric-only and four digits long,
which means when this option is enabled, the module will make sure to cover all of them - from 0000 to 9999.
The Password mode is more complex, therefore the usual online bruteforce strategies apply.

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/scanner/http/appletv_login`
3. Do: set the passwords via the `password` option, or pass a list of passwords via the `pass_file` option. Pass a user list via `user_list`.
4. Do: `run`
5. Hopefully you see something like this:
```
[+] 127.0.0.1:7000 - Login Successful: admin:adminpassword
```

## Options

### BLANK_PASSWORD

Set to `true` if an additional login attempt should be made with an empty password for every user.

### BRUTEFORCE_SPEED

How fast to bruteforce, from 0 to 5

### Onscreen

Enable if AppleTV is using the Onscreen access control

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

### VHOST

HTTP server virtual host

## Scenarios
```
msf > use auxiliary/scanner/http/appletv_login
msf6 auxiliary(scanner/http/appletv_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/appletv_login) > set password N0tpassword!
password => N0tpassword!
msf6 auxiliary(scanner/http/appletv_login) > set userfile ./USERNAMES
userfile => ./USERNAMES
msf6 auxiliary(scanner/http/appletv_login) > options

Module options (auxiliary/scanner/http/appletv_login):

   Name              Current Setting                                     Required  Description
   ----              ---------------                                     --------  -----------
   BLANK_PASSWORDS   false                                               no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                   yes       How fast to bruteforce, from 0 to 5
   DB_ALL_PASS       false                                               no        Add all passwords in the current database to the list
   Onscreen          false                                               no        Enable if AppleTV is using the Onscreen access control
   PASSWORD                                                              no        A specific password to authenticate with
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/htt  no        File containing passwords, one per line
                     p_default_pass.txt
   Proxies                                                               no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                                yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasp
                                                                                   loit.html
   RPORT             7000                                                yes       The target port (TCP)
   SSL               false                                               no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   true                                                yes       Stop guessing when a credential works for a host
   THREADS           1                                                   yes       The number of concurrent threads (max one per host)
   USERPASS_FILE                                                         no        File containing users and passwords separated by space, one pair per line
   USER_FILE                                                             no        File containing usernames, one per line
   VERBOSE           true                                                yes       Whether to print output for all attempts
   VHOST                                                                 no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/http/appletv_login) > run

[*] Attempting to login to /stop using password list
[!] 127.0.0.1:7000        - No active DB -- Credential data will not be saved!
[-] 127.0.0.1:7000        - Failed: 'AirPlay:password'
[+] 127.0.0.1:7000         - 127.0.0.1:7000 - Login Successful: WORKSTATION\sa:N0tpassword!
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/appletv_login) >
```
