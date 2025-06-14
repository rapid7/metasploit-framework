## Vulnerable Application

This module attempts to authenticate against an Oracle RDBMS instance using username and password
combinations indicated by the USER_FILE, PASS_FILE, and USERPASS_FILE options. The default wordlist
is [oracle_default_userpass.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/oracle_default_userpass.txt).

Default port for SQL*Net listener is 1521/tcp. If this port is open, try this module to login.

### Install

This module needs nmap 5.50 or above to function.  However due to an [nmap bug](https://github.com/nmap/nmap/issues/1475) versions
6.50-7.80 may not work.

```
nmap -V
apt-get install nmap
```

In addition, if you encounter errors due to OCI libraries not being found, please see the
[How to get Oracle Support working with Kali Linux](https://docs.metasploit.com/docs/using-metasploit/other/oracle-support/how-to-get-oracle-support-working-with-kali-linux.html).

For Oracle Server, please follow the following
[guide](https://tutorialforlinux.com/2019/09/17/how-to-install-oracle-12c-r2-database-on-ubuntu-18-04-bionic-64-bit-easy-guide/).

## Verification Steps

  1. Install Oracle Database server and metasploit components
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/oracle/oracle_login```
  4. Do: ```run```

## Options

  **BLANK_PASSWORDS**

  Try blank passwords for all users

  **BRUTEFORCE_SPEED**

  How fast to bruteforce, scale of 0 to 5

  **DB_ALL_CREDS**

  Try each user/password couple stored in the current database

  **DB_ALL_PASS**

  Add all passwords in the current database to the list to try

  **DB_ALL_USERS**

  Add all users in the current database to the list to try

  **NMAP_VERBOSE**

  Display nmap output

  **PASSWORD**

  Specify one password to use for all usernames

  **PASS_FILE**

  File of passwords, one per line.

  **RHOSTS**

  Target hosts, range CIDR identifier, or hosts file with syntax 'file:<path>'

  **RPORTS**

  Ports of the target

  **SID**

  Instance (SID) to authenticate against. Default `XE`

  **STOP_ON_SUCCESS**

  Stop the bruteforce attack when a valid combination is found

  **THREADS**

  Number of concurrent threads (max of one per host)

  **USERNAME**

  Specific username to try for all passwords

  **USERPASS_FILE**

  File of username and passwords, separated by space, one set per line. Default `oracle_default_userpass.txt`

  **USER_AS_PASS**

  Try the username as the password for all users

  **USER_FILE**

  File containing usernames, one per line

## Scenarios

Unfortunately due to the nmap bug mentioned above, it was not possible to create an example run.
