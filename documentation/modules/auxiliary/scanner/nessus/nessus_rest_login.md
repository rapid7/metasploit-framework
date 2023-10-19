## Vulnerable Application

This module will attempt to authenticate to a Nessus server RPC interface.

## Verification Steps
Example steps in this format (is also in the PR):

1. Start msfconsole
2. Do: `use auxiliary/scanner/nessus/nessus_rest_login`
3. Do: set usernames and passwords via the `username` and `password` options, or pass a list via `user_file` and `pass_file` options
4. Do: `run`
5. Hopefully you see somthing like this:
```
[+] 127.0.0.1:8834 - Successful: nessus:4x15pa$$w0rd
```

## Options
### BLANK_PASSWORDS
Try blank passwords for all users

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

### Proxies
A proxy chain of format type:host:port[,type:host:port][...]

### RHOSTS
The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html

### RPORT
The target port (TCP)

### SSL
Negotiate SSL/TLS for outgoing connections

### STOP_ON_SUCCESS
Stop guessing when a credential works for a host

### TARGETURI
The path to the Nessus server login API

### THREADS
The number of concurrent threads (max one per host)

### USERNAME
A specific username to authenticate as

### USERPASS_FILE
File containing users and passwords separated by space, one pair per line

### USER_AS_PASS
Try the username as the password for all users

### USER_FILE
File containing usernames, one per line

### VERBOSE
Whether to print output for all attempts

### VHOST
HTTP server virtual host

## Scenarios
Specific demo of using the module that might be useful in a real world scenario.

```
msf > use scanner/nessus/nessus_rest_login
msf6 auxiliary(scanner/nessus/nessus_rest_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/nessus/nessus_rest_login) > set password N0tpassword!
password => N0tpassword!
msf6 auxiliary(scanner/nessus/nessus_rest_login) > set username notuser
username => notuser 
msf6 auxiliary(scanner/nessus/nessus_rest_login) > run

[*] Attempting to login to /stop using password list
[+] 127.0.0.1:8834         -    Success: 'notuser:N0tpassword'!
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/nessus/nessus_rest_login) >
```