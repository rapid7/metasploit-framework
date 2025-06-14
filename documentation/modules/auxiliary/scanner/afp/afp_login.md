## Vulnerable Application

Apple Filing Protocol (AFP) is Apple's file sharing protocol similar to SMB, and NFS. This module attempts to brute force authentication credentials for AFP.

References:

* [AFP_Reference](https://developer.apple.com/library/mac/documentation/Networking/Reference/AFP_Reference/Reference/reference.html)
* [AFP_Security](https://developer.apple.com/library/mac/documentation/networking/conceptual/afp/AFPSecurity/AFPSecurity.html)

### Kali 2019.3 Install Instructions

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

  1. Start msfconsole
  2. Do: `use modules/auxiliary/scanner/afp/afp_login`
  3. Do: `set RHOSTS [ip]`
  4. Do: `run`

## Scenarios

### A run on Kali Linux 2019.3 and Netatalk 3.1.12

  ```
  msf > use modules/auxiliary/scanner/afp/afp_login
  msf auxiliary(scanner/afp/afp_login) > set USERNAME tuser
  msf auxiliary(scanner/afp/afp_login) > set PASSWORD myPassword
  msf auxiliary(scanner/afp/afp_login) > set RHOST 172.17.0.2
  msf auxiliary(scanner/afp/afp_login) > run
    [*] 172.17.0.2:548 - Scanning IP: 172.17.0.2
    [*] 172.17.0.2:548 - Login Successful: tuser:myPassword
  ```
