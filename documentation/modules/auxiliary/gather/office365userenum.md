## Vulnerable Application

External python module compatible with v2 and v3.

Enumerate valid usernames (email addresses) from Office 365 using ActiveSync.
Differences in the HTTP Response code and HTTP Headers can be used to differentiate between:

 - Valid Username (Response code 401)
 - Valid Username and Password without 2FA (Response Code 200)
 - Valid Username and Password with 2FA (Response Code 403)
 - Invalid Username (Response code 404 with Header X-CasErrorCode: UserNotFound)

Note this behaviour appears to be limited to Office365, MS Exchange does not appear to be affected.

Microsoft Security Response Center stated on 2017-06-28 that this issue does not "meet the bar for security servicing". As such it is not expected to be fixed any time soon.

This script is maintaing the ability to run independently of MSF.

Office365's implementation of ActiveSync is vulnerable.

## Verification Steps

  1. Create a file containing candidate usernames (aka email addresses), one per line.
  2. Do: ```use auxiliary/gather/office365userenum```
  3. Do: ```set users [USER_FILE]``` with the file you created.
  4. Do: ```run```
  5. Valid and Invalid usernames will be printed out to the screen. 

## Options

  LOGFILE  =   Output file to use for verbose logging.
  OUTPUT   =   Output file for results.
  PASSWORD =   Password to use during enumeration. Note this must exist
               but does not necessarily need to be valid. If it is
               found to be valid for an account it will be reported.
  THREADS  =   Number of concurrent requests to use during enumeration.
  TIMEOUT  =   HTTP request timeout to use during enumeration.
  URL      =   URL of Office365 ActiveSync service.
  USERS    =   Input fie containing candidate usernames, one per line.
  VERBOSE  =   Enable/Disable DEBUG logging


## Scenarios

The following demonstrates basic usage, using the supplied users wordlist
and default options.

```
msf5 auxiliary(gather/office365userenum) > set users /home/msfdev/users
users => /home/msfdev/users
msf5 auxiliary(gather/office365userenum) > run

[*] 

.       .1111...          | Title: office365userenum.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm@sec-1.com
1                  01..   | Description:
                    ..    | Enumerate valid usernames from Office 365 using
                   ..     | ActiveSync.
GrimHacker        ..      | Requires: Python 2.7 or 3.6, python-requests
                 ..       |
grimhacker.com  ..        |
@grimhacker    ..         |
----------------------------------------------------------------------------
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to redistribute it
    under certain conditions. See GPLv2 License.
----------------------------------------------------------------------------

[+] 401 VALID_USER valid_username@example.com:Password1
[-] 404 INVALID_USER invalid_username@example.com:Password1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
