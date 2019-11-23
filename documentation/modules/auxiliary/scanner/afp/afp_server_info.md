## Vulnerable Application

Apple Filing Protocol (AFP) is Apple's file sharing protocol similar to SMB, and NFS.  This module will gather information about the service.
Netatalk is a Linux implementation of AFP.

The following was done on Ubuntu 16.04, and is largely based on [missingreadme.wordpress.com](https://missingreadme.wordpress.com/2010/05/08/how-to-set-up-afp-filesharing-on-ubuntu/):

  1. `sudo apt-get install netatalk`
  2. edit `/etc/default/netatalk` and add the following lines:
    ```
    ATALKD_RUN=no
    PAPD_RUN=no
    CNID_METAD_RUN=yes
    AFPD_RUN=yes
    TIMELORD_RUN=no
    A2BOOT_RUN=no
    ```
  3. Restart the service: `sudo /etc/init.d/netatalk restart`

## Verification Steps

  1. Install and configure afp (or netatalk in a Linux environment)
  2. Start msfconsole
  3. Do: `auxiliary/scanner/afp/afp_server_info`
  4. Do: set RHOSTS [ip]
  5. Do: `run`

## Scenarios

  A run against the configuration from these docs

  ```
  msf5 auxiliary(scanner/acpp/login) > use auxiliary/scanner/afp/afp_server_info
  msf5 auxiliary(scanner/afp/afp_server_info) > set rhosts 1.1.1.1
  rhosts => 1.1.1.1
  msf5 auxiliary(scanner/afp/afp_server_info) > run

  [*] 1.1.1.1:548 - AFP 1.1.1.1 Scanning...
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548:548 AFP:
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548 Server Name: ubuntu
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548  Server Flags:
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Super Client: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  UUIDs: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  UTF8 Server Name: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Open Directory: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Reconnect: false
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Server Notifications: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  TCP/IP: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Server Signature: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Server Messages: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Password Saving Prohibited: false
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Password Changing: false
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  Copy File: true
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548  Machine Type: Netatalk2.2.5
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548  AFP Versions: AFP2.2, AFPX03, AFP3.1, AFP3.2, AFP3.3
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548  UAMs: Cleartxt Passwrd, DHX2
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548  Server Signature: 975394e16633312406281959287fcbd9
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548  Server Network Address:
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548     *  1.1.1.1
  [*] 1.1.1.1:548 - AFP 1.1.1.1:548   UTF8 Server Name: ubuntu
  [*] 1.1.1.1:548 - Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
