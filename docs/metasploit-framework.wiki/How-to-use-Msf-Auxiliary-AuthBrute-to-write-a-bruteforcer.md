# How to use Msf::Auxiliary::AuthBrute to write a bruteforcer
The ```Msf::Auxiliary::AuthBrute``` mixin should no longer be used to write a login module, you should try our [[LoginScanner API|./Creating-Metasploit-Framework-LoginScanners.md]] instead. However, some of the datastore options are still needed, so let's go over them right quick.

### Regular options

* **USERNAME** - (String) A specific username to authenticate as.
* **PASSWORD** - (String) A specific password to authenticate with.
* **USER_FILE** - (String) File containing usernames, one per line.
* **PASS_FILE** - (String) File containing passwords, one per line.
* **USERPASS_FILE** - (String) File containing users and passwords separated by space, one pair per line.
* **BRUTEFORCE_SPEED** - (Integer) How fast to bruteforce, from 0 to 5.
* **VERBOSE** - (Boolean) Whether to print output for all attempts.
* **BLANK_PASSWORDS** - (Boolean) Try blank passwords for all users.
* **USER_AS_PASS** - (Boolean) Try the username as the password for all users.
* **DB_ALL_CREDS** - (Boolean) Try each user/password couple stored in the current database.
* **DB_ALL_USERS** - (Boolean) Add all users in the current database to the list.
* **STOP_ON_SUCCESS** - (Boolean) Stop guessing when a credential works for a host.

### Advanced options

* **REMOVE_USER_FILE** - (Boolean) Automatically delete the USER_FILE on module completion.
* **REMOVE_PASS_FILE** - (Boolean) Automatically delete the PASS_FILE on module completion.
* **REMOVE_USERPASS_FILE** - (Boolean) Automatically delete the USERPASS_FILE on module completion.
* **MaxGuessesPerService** - (Integer) Maximum number of credentials to try per service instance. If set to zero or a non-number, this option will not be used.
* **MaxMinutesPerService** - (Integer) Maximum time in minutes to bruteforce the service instance. If set to zero or a non-number, this option will not be used.
* **MaxGuessesPerUser** - (Integer) Maximum guesses for a particular username for the service instance. Note that users are considered unique among different services, so a user at 10.1.1.1:22 is different from one at 10.2.2.2:22, and both will be tried up to the MaxGuessesPerUser limit.	If set to zero or a non-number, this option will not be used.

### Reference

- <https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/auxiliary/auth_brute.rb>
