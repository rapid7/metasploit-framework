The Msf::Auxiliary::AuthBrute should no longer be the mixin used to write a login module, you should try our [LoginScanner API](https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners) instead. However, some of the datastore options are still needed, so let's go over them right quick.

### Regular options

* **USERNAME** - (String) 
* **PASSWORD** - (String) 
* **USER_FILE** - (String) 
* **PASS_FILE** - (String) 
* **USERPASS_FILE** - (String)  
* **BRUTEFORCE_SPEED** - (Integer) 
* **VERBOSE** - (Boolean)
* **BLANK_PASSWORDS** - (Boolean) 
* **USER_AS_PASS** - (Boolean) 
* **DB_ALL_CREDS** - (Boolean) 
* **DB_ALL_USERS** - (Boolean) 
* **STOP_ON_SUCCESS** - (Boolean) 

### Advanced options

* **REMOVE_USER_FILE** - (Boolean)
* **REMOVE_PASS_FILE** - (Boolean)
* **REMOVE_USERPASS_FILE** - (Boolean)
* **MaxGuessesPerService** - (Integer) 
* **MaxMinutesPerService** - (Integer) 
* **MaxGuessesPerUser** - (Integer) 