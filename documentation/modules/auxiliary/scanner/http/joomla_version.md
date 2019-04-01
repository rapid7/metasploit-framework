## Intro

This module scans for Joomla Content Management System running on a web server.

## Usage

```
msf5 > use auxiliary/scanner/http/joomla_version 
msf5 auxiliary(scanner/http/joomla_version) > set rhosts 192.168.2.39
rhosts => 192.168.2.39
msf5 auxiliary(scanner/http/joomla_version) > run

[*] Server: Apache/2.4.29 (Ubuntu)
[+] Joomla version: 3.8.2
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming using Joomscan

```
# joomscan -u 192.168.2.39
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.5
    +---++---==[Update Date : [2018/03/13]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : KLOT
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://192.168.2.39 ...

[+] Detecting Joomla Version
[++] Joomla 3.8.2
...snip...
```