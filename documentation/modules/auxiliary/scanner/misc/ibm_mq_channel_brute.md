
## Vulnerable Application

  * IBM Downloads page: https://developer.ibm.com/messaging/mq-downloads/
  * Tested on IBM MQ 7.5, 8 and 9
  * Usage:
    * Download and install MQ Server
    * Create a new Queue Manager
    * Create a new channel (without SSL)
    * Run the module

## Verification Steps

  Example steps in this format (is also in the PR):

  1. Install IBM MQ Server 7.5, 8, or 9
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/misc/ibm_mq_channel_brute```
  4. Do: ```set channels_file <channel_list_file>```
  5. Do: ```set rhosts <target_IP>```
  6. Do: ```set rport <port>```
  7. Do: ```run```
  
  Example output:
  ```
  msf auxiliary(scanner/misc/ibm_mq_channel_brute) > run
  
[*] 10.1.1.144:1414       - Found channel: TEST.CHANNEL, IsEncrypted: False, IsMQI: True
[*] 10.1.1.144:1414       - Found channel: SYSTEM.ADMIN.SVRCONN, IsEncrypted: False, IsMQI: True

[+] 10.1.1.144:1414       - Channels found: ["TEST.CHANNEL", "SYSTEM.ADMIN.SVRCONN"]
[+] 10.1.1.144:1414       - Unencrypted MQI Channels found: ["TEST.CHANNEL", "SYSTEM.ADMIN.SVRCONN"]

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```

## Options

  **The CHANNELS_FILE option**

  This option should contain the path to a text file which contains a list of channel names that will be checked. One channel name per line.

## Scenarios

  This module can be used to identify a list of channel names that are configured on the Queue Manager. Additionally, the module will return whether each identified channel uses SSL and if it MQI type.
  After obtaining a list of valid channel names, these can be used to further enumerate the MQ installation. For example, the ibm_mq_enum module can be executed using a valid channel name in order to obtain information regarding the Queue Manager.
