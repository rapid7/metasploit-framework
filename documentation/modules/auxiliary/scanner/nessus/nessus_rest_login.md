## Vulnerable Application

This module will attempt to authenticate to a Nessus server's RPC interface.

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/scanner/nessus/nessus_rest_login`
3. Do: set usernames and passwords via the `username` and `password` options, or pass a list via `user_file` and `pass_file` options
4. Do: `run`
5. Hopefully you see somthing like this:
```
[+] 127.0.0.1:8834 - Successful: nessus:4x15pa$$w0rd
```

### Installation Steps
This is a summary of installation steps for downloading, installing and running Nessus on Debian. They are as follows:

1. Go to tenable.com.
2. Download the latest version of nessus. Take note of the version number.
3. Run the following command in the same directory as the .deb file: `dpkg -i Nessus-<version number>-debian6_amd64.deb`
4. Restart nessus with the `systemctl start nessusd` command.
5. Use your browser to access port 8834 on localhost (https://localhost:8834).

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
