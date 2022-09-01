## Vulnerable Application

The R Services (rexecd, rlogind, and rshd) are a suite of unencrypted remote command/login services developed in the 1980s.
These services are all but unused in modern computing, as they have been replace by telnet and ssh.

`rsh` relies on host names as a security mechanism.  Utilizing `+` can wildcard so any computer can connect.  In the following
config, we'll utilize that wildcarded setting to simplify our exploitation.  **This is a glaring security issue!!!**
However, there are exceptions to this in proprietary Unix systems which may include other mechanisms such as Kerberos
([AIX](https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.cmds4/rsh.htm))

If you encounter `Host address mismatch for `..., you may need to adjust your `/etc/hosts` file accordingly.

The following was done on Kali linux:

  1. `apt-get install rsh-server` which includes: `rexecd`, `rlogind` and `rshd`.
  2. ```echo "+" > ~/.rhosts```
  3. Start the service: `service openbsd-inetd start`

## Verification Steps

  1. Install and configure rexec
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/rservices/rsh_login`
  4. Do: `set rhosts`
  5. Set any other credentials that will need to be set
  6. Do: `run`

## Scenarios

  A run against the configuration from these docs

  ```
    msf > use auxiliary/scanner/rservices/rsh_login 
    msf auxiliary(rsh_login) > set rhosts 10.1.2.3
    rhosts => 10.1.2.3
    msf auxiliary(rsh_login) > set username root
    username => root
    msf auxiliary(rsh_login) > run
    
    [*] 10.1.2.3:514     - 10.1.2.3:514 - Starting rsh sweep
    [*] 10.1.2.3:514     - 10.1.2.3:514 - Attempting rsh with username 'root' from 'root'
    [+] 10.1.2.3:514     - 10.1.2.3:514, rsh 'root' from 'root' with no password.
    [!] 10.1.2.3:514     - *** auxiliary/scanner/rservices/rsh_login is still calling the deprecated report_auth_info method! This needs to be updated!
    [!] 10.1.2.3:514     - *** For detailed information about LoginScanners and the Credentials objects see:
    [!] 10.1.2.3:514     -      https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners
    [!] 10.1.2.3:514     -      https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-HTTP-LoginScanner-Module
    [!] 10.1.2.3:514     - *** For examples of modules converted to just report credentials without report_auth_info, see:
    [!] 10.1.2.3:514     -      https://github.com/rapid7/metasploit-framework/pull/5376
    [!] 10.1.2.3:514     -      https://github.com/rapid7/metasploit-framework/pull/5377
    [*] Command shell session 1 opened (10.1.2.3:1023 -> 10.1.2.3:514) at 2017-05-11 19:56:46 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

## Confirming

At the time of writing this, there was no `nmap` script equivalent.  Most modern systems have also replaced `rsh` with `ssh`.
