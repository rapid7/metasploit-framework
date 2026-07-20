## Vulnerable Application

POP3 is an application-layer Internet standard protocol used by e-mail clients
to retrieve e-mail from a mail server.

This module in particular attempts to authenticate to a POP3 service.
The default wordlists are:
- [unix_users.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/unix_users.txt) for users and
- [unix_passwords.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/unix_passwords.txt) for passowords
## Verification Steps

1. Install and configure a pop3 server (ex: with dovecot)
2. Start msfconsole
3. Do: `use auxiliary/scanner/pop3/pop3_login`
4. Do: `set rhosts [IP]`
5. Do: `run`

## Options

### ANONYMOUS_LOGIN

  Attempt to login with a blank username and password

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

  Newline separated list of probable users passwords. Default depends on install location,
  however it will be within metasploit-framework/data/wordlists/unix_passwords.txt

### STOP_ON_SUCCESS

  Stop guessing when a credential works for a host

### THREADS

  The number of concurrent threads (max one per host)

### USERNAME

  A specific username to authenticate as

### USERPASS_FILE

  File containing users and pass words separated by space, one pair per line

### USER_AS_PASS

  Try the username as the password for all users


### USER_FILE

  Newline separated list of probable users accounts. Default depends on install location,
  however it will be within metasploit-framework/data/wordlists/unix_users.txt

                     
### VERBOSE

  Whether to print output for all attempts


## Scenarios

### Dovecot on Kali-Linux




First we need to install an email server, here we will use dovecot:

- `sudo apt install dovecot-core dovecot-pop3d` version 2.3 will be installed

Then we can configure it

- In /etc/dovecot/dovecot.conf uncomment the line `#protocols = pop3 imap lmtp`

- In /etc/dovecot/conf.d/10-ssl.conf change the line `ssl = yes` to `ssl = no` (obviously this is bad practice)

Then we create a new user

- `sudo useradd -m alice && echo "alice:password123" | sudo chpasswd`

We can now start the server with `sudo systemctl start dovecot`

Now we can go into msfconsole:

```
msf > use auxiliary/scanner/pop3/pop3_login
msf auxiliary(scanner/pop3/pop3_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/pop3/pop3_login) > set username alice
username => alice
msf auxiliary(scanner/pop3/pop3_login) > set password password123
password => password123
msf auxiliary(scanner/pop3/pop3_login) > run
[+] 127.0.0.1:110         - 127.0.0.1:110         - Success: 'alice:password123' '+OK Logged in.  '
[!] 127.0.0.1:110         - No active DB -- Credential data will not be saved!
[*] 127.0.0.1:110         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
