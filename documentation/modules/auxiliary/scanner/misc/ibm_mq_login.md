## Vulnerable Application

* IBM Downloads page: https://developer.ibm.com/messaging/mq-downloads/
* Tested on IBM MQ 7.5, 8 and 9
* Usage:
  * Download and install MQ Server from the above link
  * Create a new Queue Manager
  * Create a new channel (without SSL)
  * Allow remote connections for admin users by removing the CHLAUTH record that denies all users or configure access for a specific username.
  * Run the module
 
 ## Verification Steps
  Example steps in this format (is also in the PR):
  1. Install IBM MQ Server 7.5, 8, or 9
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/misc/ibm_mq_login```
  4. Do: ```set channel <admin_channel_name_without_ssl>```
  5. Do: ```set queue_manager <queue_manager_name>```
  5. Do: ```set usernames_file <list_of_usernames>```
  6. Do: ```set rhosts <target_IP>```
  7. Do: ```set rport <port>```
  8. Do: ```run```
  
  Example output:
  ```
msf auxiliary(scanner/misc/ibm_mq_login) > run

[*] 10.1.1.10:1416        - Found username: admin
[*] 10.1.1.10:1416        - Found username: test

[+] 10.1.1.10:1416        - 10.1.1.10:1416 Valid usernames found: ["admin", "test"]

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
   ```
 ## Options
   **The USERNAMES_FILE option**
   
   This option should contain the path to a text file which contains a list of usernames that will be checked. One username per line.
   
   **The QUEUE_MANAGER option**
   
   This option should contain the name of the target Queue Manager.
   
   **The CHANNEL option**
   
   This option should contain the name of a server-connection channel that will be used to connect to the Queue Manager.
   
 ## Scenarios
   This module can be used to identify a list of usernames that are allowed to connect to the Queue Manager. This module requires the name of a valid server-connection channel, the Queue Manager's name which can be obtained by running the following 2 modules:
   * ```auxiliary/scanner/misc/ibm_mq_channel_brute```
   * ```auxiliary/scanner/misc/ibm_mq_enum```
   After identifying a valid username, MQ Explorer can be used to connect to the Queue Manager using the information gathered.
