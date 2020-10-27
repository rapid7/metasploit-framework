
## Vulnerable Application

This module attempts to find files on a TFTP server.  The default wordlist is [tftp.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/tftp.txt).
This module will NOT attempt to download the entire file, it simply pulls the first 3 bytes to verify the file exists.

### Install

On Kali 2019.4 (rolling) one of the  TFTP server is the package `tftpd-hpa`.  This can be installed as follows:

```
apt-get install tftpd-hpa
systemctl start tftpd-hpa
```

This creates the root tftp directory in `/srv/tftp`.  

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/tftp/tftpbrute```
  4. Do: ```run```

## Options

  **DICTIONARY**

  The newline separated list of files to find.  Default depends on install location, however it will be within `metasploit-framework/data/wordlists/tftp.txt`.

## Scenarios

### tftpd-hpa on Kali linux

First, create a file to find:

```
echo "hello world" > /srv/tftp/test.txt
```

Now we can find the file:

```
msf5 > use auxiliary/scanner/tftp/tftpbrute 
msf5 auxiliary(scanner/tftp/tftpbrute) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf5 auxiliary(scanner/tftp/tftpbrute) > set verbose true
verbose => true
msf5 auxiliary(scanner/tftp/tftpbrute) > run

[+] Found test.txt on 1.1.1.1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/tftp/tftpbrute) > 
```
