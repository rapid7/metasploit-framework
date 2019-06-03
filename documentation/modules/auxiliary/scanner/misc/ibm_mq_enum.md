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
  3. Do: ```use auxiliary/scanner/misc/ibm_mq_enum```
  4. Do: ```set channel <channel_name>```
  5. Do: ```set rhosts <target_IP>```
  6. Do: ```set rport <port>```
  7. Do: ```run```
  
  Example output:
```
msf auxiliary(scanner/misc/ibm_mq_enum) > run

[+] 10.1.1.144:           - 10.1.1.144:1414 - Queue Manager Name: TESTQM - MQ Version: 9.1.0.0
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

## Options
   **The CHANNEL option**
   
   This option should contain the name of a valid MQ channel. This can be obtained using the module ```auxiliary/scanner/misc/ibm_mq_channel_brute```

## Scenarios
   This module can be used to obtain the Queue Manager name as well as the version of the MQ being used on the target host. When the Queue Manager name and a valid MQI channel name without SSL is known , the module ```auxiliary/scanner/misc/ibm_mq_login``` can be used to identify usernames that can authenticate to the Queue Manager.
