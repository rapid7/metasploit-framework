## Description

This module determines if usernames are valid on a server running Apache with the UserDir directive enabled. 
It takes advantage of Apache returning different error codes for usernames that do not exist and for usernames with no `public_html` directory.

## Vulnerable Application

This module was tested on Apache 2.4.18.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/apache_userdir_enum```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Demo

![apache_userdir_enum_demo](https://github.com/jkollross/metasploit-framework/releases/download/untagged-874b8904bb448c5d0fac/2019-12-10_20-55-02.gif)
