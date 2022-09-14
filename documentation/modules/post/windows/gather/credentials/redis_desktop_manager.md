## Vulnerable Application
[RedisDesktopManager](https://github.com/uglide/RedisDesktopManager) stores its credentials
in a JSON file in plaintext. This module allow users who have successfully compromised a machine
running RedisDesktopManager to extract these credentials from the compromised system so that they can be reused
for future attacks or for password analysis.

### Setup Steps
1. Download the latest installer of RedisdDesktopManager from https://github.com/uglide/RedisDesktopManager/releases.
   However you need to be subscribed to be able to run these editions. Therefore it is recommended that you download the Windows version from https://github.com/lework/RedisDesktopManager-Windows/releases and use these for testing if you don't have an existing Redis subscription.
2. Run the installer, follow the prompts, and select all the default settings.
3. Once everything has been installed, start RedisDesktopManager and click on `Connect To Redis Server`.
4. Click `OK` after filling in the connection information, including the username and password to log into the Redis server as.

## Verification Steps
1. `msfconsole`
2. Get a Meterpreter session on a Windows system
3. `use post/windows/gather/credentials/redis_desktop_manager`
4. `set SESSION <session number of the Meterpreter session>`
5. `run`
6. Verify that the module was able to extract the connection credentials you entered during the `Setup Steps` phrase.


## Options
### REGEX
Users can set their own regular expressions that will be utilized to
determine which credentials to extract. The default is set to `^password`.

### VERBOSE
By default this option is turned off. When turned on, the module will show information on files
which aren't extracted and information that is not directly related to the artifact output.


### STORE_LOOT
This option is turned on by default and will cause the module to save
the stolen artifacts/files to the loot files on the machine running Metasploit.
This is required for extracting credentials from files using regexp,
JSON, XML, and SQLite queries.


### EXTRACT_DATA
This option is turned on by default and will perform the data extraction using the
predefined regular expression. The `STORE_LOOT` option must be turned on in
order for this to work.

## Scenarios

