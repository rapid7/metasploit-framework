## Vulnerable Application

This module will test AMQP logins on a range of machines and report successful logins.  If you have loaded a database
plugin and connected to a database this module will record successful logins and hosts so you can track your access.

## Verification Steps

1. Install RabbitMQ and start it
   1. To use Docker, run: `docker run --rm -it --hostname "$(hostname)" -p 15672:15672 -p 5672:5672 rabbitmq:3-management`
2. Start msfconsole
3. Do: `use auxiliary/scanner/amqp/amqp_login`
4. Do: `set rhosts`
5. Do: set usernames and passwords via any of the available options
6. Do: `run`

## Options

### BLANK_PASSWORD

Boolean value on if an additional login attempt should be attempted with an empty password for every user.

### PASSWORD

Password to try for each user.

### PASS_FILE

A file containing a password on every line. Kali linux example: `/usr/share/wordlists/metasploit/password.lst`

### STOP_ON_SUCCESS

If a valid login is found on a host, immediately stop attempting additional logins on that host.

### USERNAME

Username to try for each password.

### USERPASS_FILE

A file containing a username and password, separated by a space, on every line. An example line would be `username
password`.

### USER_AS_PASS

Boolean value on if an additional login attempt should be attempted with the password as the username.

### USER_FILE

A file containing a username on every line.

### VERBOSE

Show a failed login attempt. This can get rather verbose when large `USER_FILE`s or `PASS_FILE`s are used. A failed
attempt will look similar to the following:

```
[-] 192.168.159.128:5672 - LOGIN FAILED: admin:Password1! (Incorrect: ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.)
```

## Option Combinations

It is important to note that usernames and passwords can be entered in multiple combinations. For instance, a password
could be set in `PASSWORD`, be part of either `PASS_FILE` or `USERPASS_FILE`, be guessed via `USER_AS_PASS` or
`BLANK_PASSWORDS`. This module makes a combination of all of the above when attempting logins. So if a password is set
in `PASSWORD`, and a `PASS_FILE` is listed, passwords will be generated from BOTH of these.

## Scenarios
### RabbitMQ 3.11.10 on Docker

The Docker container listens on 5672/tcp without SSL. There's also an administrative site running on 15672/tcp where
users can be added. The default credentials to login are `guest` / `guest`. A new `admin` account was added for this
example.

```
msf6 > use auxiliary/scanner/amqp/amqp_login 
msf6 auxiliary(scanner/amqp/amqp_login) > set RHOSTS 192.168.159.128
RHOSTS => 192.168.159.128
msf6 auxiliary(scanner/amqp/amqp_login) > set USERNAME admin
USERNAME => admin
msf6 auxiliary(scanner/amqp/amqp_login) > set PASS_FILE data/wordlists/unix_passwords.txt
PASS_FILE => data/wordlists/unix_passwords.txt
msf6 auxiliary(scanner/amqp/amqp_login) > set RPORT 5672
RPORT => 5672
msf6 auxiliary(scanner/amqp/amqp_login) > set SSL false
[!] Changing the SSL option's value may require changing RPORT!
SSL => false
msf6 auxiliary(scanner/amqp/amqp_login) > run

[-] 192.168.159.128:5672 - LOGIN FAILED: admin:Password1! (Incorrect: ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.)
[-] 192.168.159.128:5672 - LOGIN FAILED: admin:admin (Incorrect: ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.)
[-] 192.168.159.128:5672 - LOGIN FAILED: admin:123456 (Incorrect: ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.)
[-] 192.168.159.128:5672 - LOGIN FAILED: admin:12345 (Incorrect: ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.)
[-] 192.168.159.128:5672 - LOGIN FAILED: admin:123456789 (Incorrect: ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.)
[+] 192.168.159.128:5672 - Login Successful: admin:password
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/amqp/amqp_login) > 
```
