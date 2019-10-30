## Introduction

This module scans for Joomla Content Management System running on a web server for components/plugins.
The list can be found in [data/wordlists/joomla.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/joomla.txt). 

## Usage

```
msf5 > use auxiliary/scanner/http/joomla_plugins 
msf5 auxiliary(scanner/http/joomla_plugins) > set rhosts 192.168.2.39
rhosts => 192.168.2.39
msf5 auxiliary(scanner/http/joomla_plugins) > run

[+] Plugin: /?1.5.10-x 
[+] Plugin: /?1.5.11-x-http_ref 
[+] Plugin: /?1.5.11-x-php-s3lf 
[+] Plugin: /?1.5.3-path-disclose 
[+] Plugin: /?1.5.3-spam 
[+] Plugin: /?1.5.8-x 
[+] Plugin: /?1.5.9-x 
[+] Plugin: /?j1012-fixate-session 
[+] Plugin: /administrator/ 
[+] Plugin: /administrator/components/ 
[+] Plugin: /administrator/components/com_admin/ 
[+] Plugin: /administrator/index.php?option=com_djartgallery&task=editItem&cid[]=1'+and+1=1+--+ 
[+] Plugin: /administrator/index.php?option=com_searchlog&act=log 
[+] Plugin: /components/com_banners/ 
[+] Plugin: /components/com_content/ 
[+] Page: /index.php?option=com_content
[+] Plugin: /components/com_mailto/ 
[+] Plugin: /components/com_search/ 
[+] Page: /index.php?option=com_search
[+] Plugin: /components/com_users/ 
[+] Page: /index.php?option=com_users
[+] Plugin: /index.php?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd&jat3action=gzip&amp;type=css&v=1 
[+] Vulnerability: Potential LFI
[+] Plugin: /index.php?option=com_newsfeeds&view=categories&feedid=-1%20union%20select%201,concat%28username,char%2858%29,password%29,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30%20from%20jos_users-- 
[+] Page: /index.php?option=com_newsfeeds&view=categories&feedid=-1%20union%20select%201,concat%28username,char%2858%29,password%29,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30%20from%20jos
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
## Confirming using Joomscan

The `-ec` flag is used to enumerate components/plugins.

```
# joomscan -u 192.168.2.39 -ec
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

...snip...

[+] Enumeration component (com_ajax)
[++] Name: com_ajax
Location : http://192.168.2.39/components/com_ajax/
Directory listing is enabled : http://192.168.2.39/components/com_ajax/


[+] Enumeration component (com_banners)
[++] Name: com_banners
Location : http://192.168.2.39/components/com_banners/
Directory listing is enabled : http://192.168.2.39/components/com_banners/


[+] Enumeration component (com_contact)
[++] Name: com_contact
Location : http://192.168.2.39/components/com_contact/
Directory listing is enabled : http://192.168.2.39/components/com_contact/


[+] Enumeration component (com_content)
[++] Name: com_content
Location : http://192.168.2.39/components/com_content/
Directory listing is enabled : http://192.168.2.39/components/com_content/


[+] Enumeration component (com_contenthistory)
[++] Name: com_contenthistory
Location : http://192.168.2.39/components/com_contenthistory/
Directory listing is enabled : http://192.168.2.39/components/com_contenthistory/


[+] Enumeration component (com_fields)
[++] Name: com_fields
Location : http://192.168.2.39/components/com_fields/
Directory listing is enabled : http://192.168.2.39/components/com_fields/


[+] Enumeration component (com_finder)
[++] Name: com_finder
Location : http://192.168.2.39/components/com_finder/
Directory listing is enabled : http://192.168.2.39/components/com_finder/


[+] Enumeration component (com_mailto)
[++] Name: com_mailto
Location : http://192.168.2.39/components/com_mailto/
Directory listing is enabled : http://192.168.2.39/components/com_mailto/
Installed version : 3.1


[+] Enumeration component (com_media)
[++] Name: com_media
Location : http://192.168.2.39/components/com_media/
Directory listing is enabled : http://192.168.2.39/components/com_media/


[+] Enumeration component (com_newsfeeds)
[++] Name: com_newsfeeds
Location : http://192.168.2.39/components/com_newsfeeds/
Directory listing is enabled : http://192.168.2.39/components/com_newsfeeds/


[+] Enumeration component (com_search)
[++] Name: com_search
Location : http://192.168.2.39/components/com_search/
Directory listing is enabled : http://192.168.2.39/components/com_search/


[+] Enumeration component (com_users)
[++] Name: com_users
Location : http://192.168.2.39/components/com_users/
Directory listing is enabled : http://192.168.2.39/components/com_users/


[+] Enumeration component (com_wrapper)
[++] Name: com_wrapper
Location : http://192.168.2.39/components/com_wrapper/
Directory listing is enabled : http://192.168.2.39/components/com_wrapper/
Installed version : 3.1
```
