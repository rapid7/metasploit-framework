## Vulnerable Application

Jenkins is an open source continuous integration/continuous delivery and deployment (CI/CD) automation software DevOps 
tool written in the Java programming language. It is used to implement CI/CD workflows, called pipelines, with packages 
for Windows, Linux, macOS and other Unix-like operating systems. This module attempts to login to Jenkins with username 
and password combinations.

Jenkins can be downloaded from [jenkins.io](https://jenkins.io/) where
binaries are available for a variety of operating systems. Both LTS and weekly
builds are available.

This exploit has been tested against the following Jenkins versions:
* 2.411
* 2.410
* 2.409
* 2.401.1
* 2.346.3
* 2.103
* 1.565

## Verification Steps

1. Install Jenkins and start it
2. Start `msfconsole`
3. Do: `use auxiliary/scanner/http/jenkins_login`
4. Do: `set rhosts`
5. Do: set usernames and passwords via the `username` and `password` options, or pass a list via `user_file` and `pass_file` options
5. Do: `run`
6. You will hopefully see something similar to, followed by a session:

```
[+] 127.0.0.1:8080 - Login Successful: admin:a6e7999109654c77a4d0b1222db1cad5
```

## Options

### BLANK_PASSWORD

Boolean value on if an additional login attempt should be attempted with an empty password for every user.

### BRUTEFORCE_SPEED

How fast to bruteforce, from 0 to 5

### DB_ALL_CREDS

Boolean value on to try each user/password couple stored in the current database

### DB_ALL_PASS

Boolean value on to add all passwords in the current database to the list

### DB_ALL_USERS

Boolean value on to add all users in the current database to the list

### DB_SKIP_EXISTING

Skip existing credentials stored in the current database (Accepted: none, user, user&realm)

### HTTP_METHOD

The HTTP method to use for the login (Accepted: GET, POST)

### PASSWORD

Password to try for each user.

### PASS_FILE

A file containing a password on every line. Kali linux example: `/usr/share/wordlists/metasploit/password.lst`

### PROXIES

A proxy chain of format type:host:port[,type:host:port][...]

### RHOSTS

The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html

### RPORT

The target port (TCP)

### SSL

Boolean value on to negotiate SSL/TLS for outgoing connections

### STOP_ON_SUCCESS

Boolean value on to immediately stop attempting additional logins on that host if a valid login is found on a host

### THREADS

The number of concurrent threads (max one per host)

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

Show a failed login attempt. This can get rather verbose when a large `USER_FILE` or `PASS_FILE` is used. A failed
attempt will look similar to the following:

```
...
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:6519d020f3d743d9bd6b60b777b55f86 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:d2fbc2973ce24146adb381d32e789269 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:foo (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:bar (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:5543 (Incorrect)
...
```

## Scenarios

### Single set of credentials being passed

```
msf6 auxiliary(scanner/http/jenkins_login) > run rhost=127.0.0.1 rport=8080 username=admin password=34c27512dda149ff8bc0d0854123562c

[+] 127.0.0.1:8080 - Login Successful: admin:34c27512dda149ff8bc0d0854123562c
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Multiple credentials being passed

```
msf6 auxiliary(scanner/http/jenkins_login) > run rhost=127.0.0.1 rport=8080 user_file=users.txt pass_file=passwords.txt

[-] 127.0.0.1:8080 - LOGIN FAILED: admin:6519d020f3d743d9bd6b60b777b55f86 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:d2fbc2973ce24146adb381d32e789269 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:foo (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:bar (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:5543 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:3a4eac65719e422daf9085d3bed4275e (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:22345sasdc (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: admin:34c27512dda149ff8bc0d0854123562c (Incorrect)
[+] 127.0.0.1:8080 - Login Successful: admin:a6e7999109654c77a4d0b1222db1cad5
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:6519d020f3d743d9bd6b60b777b55f86 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:d2fbc2973ce24146adb381d32e789269 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:foo (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:bar (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:5543 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:3a4eac65719e422daf9085d3bed4275e (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:22345sasdc (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:34c27512dda149ff8bc0d0854123562c (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: foo:a6e7999109654c77a4d0b1222db1cad5 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:6519d020f3d743d9bd6b60b777b55f86 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:d2fbc2973ce24146adb381d32e789269 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:foo (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:bar (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:5543 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:3a4eac65719e422daf9085d3bed4275e (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:22345sasdc (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:34c27512dda149ff8bc0d0854123562c (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: bar:a6e7999109654c77a4d0b1222db1cad5 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:6519d020f3d743d9bd6b60b777b55f86 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:d2fbc2973ce24146adb381d32e789269 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:foo (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:bar (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:5543 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:3a4eac65719e422daf9085d3bed4275e (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:22345sasdc (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:34c27512dda149ff8bc0d0854123562c (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test:a6e7999109654c77a4d0b1222db1cad5 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:6519d020f3d743d9bd6b60b777b55f86 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:d2fbc2973ce24146adb381d32e789269 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:foo (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:bar (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:5543 (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:3a4eac65719e422daf9085d3bed4275e (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:22345sasdc (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:34c27512dda149ff8bc0d0854123562c (Incorrect)
[-] 127.0.0.1:8080 - LOGIN FAILED: test2:a6e7999109654c77a4d0b1222db1cad5 (Incorrect)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
