## Vulnerable Application

This module attempts to login to an Apache Axis2 instance using username and password
combinations indicated by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
It has been verified to work on at least versions 1.4.1 and 1.6.2.

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/scanner/http/axis_login`
3. Do: set usernames and passwords via the `username` and `password` options, or pass a list via `user_file` and `pass_file` options
4. Do: `run`
5. Hopefully you see somthing like this:
```
[+] 127.0.0.1:8080 - Login Successful: axisadmin:4x15pa$$w0rd
```

## Options
List each option and how to use it.

### BLANK_PASSWORDS

Try blank passwords for all users

### BLANK_PASSWORD

Set to `true` if an additional login attempt should be made with an empty password for every user.

### BRUTEFORCE_SPEED

How fast to bruteforce, from 0 to 5

### DB_ALL_CREDS

Try each user/password couple stored in the current database

### DB_ALL_PASS

Add all passwords in the current database to the list


### DB_ALL_USERS

Add all users in the current database to the list

### DB_SKIP_EXISTING

Skip existing credentials stored in the current database (Accepted: none, user, user&realm)


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
Specific demo of using the module that might be useful in a real world scenario.

```
msf > use auxiliary/scanner/http/axis_login
msf6 auxiliary(scanner/http/axis_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/axis_login) > set password N0tpassword!
password => N0tpassword!
msf6 auxiliary(scanner/http/axis_login) > set userfile ./USERNAMES
userfile => ./USERNAMES
msf6 auxiliary(scanner/http/axis_login) > show options

Module options (auxiliary/scanner/http/axis_login):

   Name              Current Setting           Required  Description
   ----              ---------------           --------  -----------
   BLANK_PASSWORDS   false                     no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                         yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                     no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                     no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                     no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                      no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                                    no        A specific password to authenticate with
   PASS_FILE                                   no        File containing passwords, one per line
   Proxies                                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             8080                      yes       The target port (TCP)
   SSL               false                     no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   false                     yes       Stop guessing when a credential works for a host
   TARGETURI         /axis2/axis2-admin/login  no        Path to the Apache Axis Administration page
   THREADS           1                         yes       The number of concurrent threads (max one per host)
   USERNAME                                    no        A specific username to authenticate as
   USERPASS_FILE                               no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                     no        Try the username as the password for all users
   USER_FILE                                   no        File containing usernames, one per line
   VERBOSE           true                      yes       Whether to print output for all attempts
   VHOST                                       no        HTTP server virtual host

View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/http/axis_login) > run

[*] Attempting to login to /stop using password list
[!] 127.0.0.1:8080        - No active DB -- Credential data will not be saved!
[-] 127.0.0.1:8080        - Failed: 'AxisRoot:password'
[+] 127.0.0.1:8080         - 127.0.0.1:8080 - Login Successful: WORKSTATION\AxisRoot:N0tpassword!
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/axis_login) >
```
