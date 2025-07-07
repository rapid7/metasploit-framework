## Description

  This module identifies the existence of possible copies of a specific file in a given path.

## Verification Steps

1. `./msfconsole -q`
2. `set RHOSTS <rhost>`
3. `set RPORT <rport>`
4. `set PATH <filepath>`
5. `run`


## Scenarios

```
msf6 auxiliary(scanner/http/copy_of_file) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/copy_of_file) > set PATH /search_a_copy.txt
PATH => /search_a_copy.txt
msf6 auxiliary(scanner/http/copy_of_file) > run
[*] Using code '404' as not found.
[+] [127.0.0.1] Found http://127.0.0.1:80/Copy_(1)_of_search_a_copy.txt [200]
[*] Using code '404' as not found.
[+] [127.0.0.1] Found http://127.0.0.1:80/Copy_(2)_of_search_a_copy.txt [200]
[*] Using code '400' as not found.
[*] Using code '404' as not found.
[+] [127.0.0.1] Found http://127.0.0.1:80/Copy_of_search_a_copy.txt [200]
[*] Using code '404' as not found.
[*] Using code '404' as not found.
[+] [127.0.0.1] Found http://127.0.0.1:80/Copysearch_a_copy.txt [200]
[*] Using code '404' as not found.
[+] [127.0.0.1] Found http://127.0.0.1:80/_search_a_copy.txt [200]
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
