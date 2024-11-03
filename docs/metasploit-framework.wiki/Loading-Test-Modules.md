Metasploit offers inbuilt test modules which can be used for verifying Metasploit's post-exploitations work with currently opened sessions.
These modules are intended to be used by developers to test updates to ensure they don't break core functionality
and should not be used during normal operations. These modules also as part of the automated test suite within pull requests.

By default the test modules in Metasploit are not loaded when Metasploit starts. To load them, run `loadpath test/modules` after which you should see output similar to the following:

```msf
msf6 > loadpath test/modules
Loaded 38 modules:
    14 auxiliary modules
    13 exploit modules
    11 post modules
msf6 > 
```

The modules can be searched for:

```msf
msf6 > search post/test

Matching Modules
================

   #   Name                               Disclosure Date  Rank    Check  Description
   -   ----                               ---------------  ----    -----  -----------
   0   post/test/cmd_exec                 .                normal  No     Meterpreter cmd_exec test
   1   post/test/railgun                  .                normal  No     Railgun API Tests
   2   post/test/extapi                   .                normal  No     Test Meterpreter ExtAPI Stuff
   3   post/test/get_env                  .                normal  No     Test Post::Common Get Envs
   4   post/test/services                 .                normal  No     Test Post::Windows::Services
   5   post/test/all                      .                normal  No     Test all applicable post modules
... etc etc ...
```

Example of running the test module against an opened session:

```
msf6 > use post/test/cmd_exec
msf6 post(test/cmd_exec) > run session=-1
...
[*] Testing complete in 2.04 seconds
[*] Passed: 6; Failed: 0; Skipped: 0
[*] Post module execution completed
```

The `post/test/all` module is an aggregate module that can be used to quickly run all of the applicable test modules
against a currently open session:

```msf
msf6 post(test/all) > run session=-1

[*] Applicable modules:
Valid modules for x86/windows session 1
=======================================

 #   Name                          is_session_platform  is_session_type
 -   ----                          -------------------  ---------------
 0   test/railgun_reverse_lookups  Yes                  Yes
 1   test/search                   Yes                  Yes
 2   test/services                 Yes                  Yes
 3   test/meterpreter              Yes                  Yes
 4   test/cmd_exec                 Yes                  Yes
 5   test/extapi                   Yes                  Yes
 6   test/file                     Yes                  Yes
 7   test/get_env                  Yes                  Yes
 8   test/railgun                  Yes                  Yes
 9   test/registry                 Yes                  Yes
 10  test/unix                     No                   Yes
 11  test/mssql                    Yes                  No
 12  test/mysql                    Yes                  No
 13  test/postgres                 Yes                  No
 14  test/smb                      Yes                  No

[*] Running test/cmd_exec against session -1
[*] --------------------------------------------------------------------------------
... etc etc ...

[*] Running test/extapi against session -1
[*] --------------------------------------------------------------------------------
... etc etc ...
```
