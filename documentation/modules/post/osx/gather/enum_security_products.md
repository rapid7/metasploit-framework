## Vulnerable Application

OSX Antivirus Hunter module enumerates devices for the presence of common security products e.g. antivirus, EDR etc.
by matching the running processes on a device against a pre-selected list of security products.
Running this file does not require root privileges and is entirely independent on the release of the OSX device and its
architecture. Through the **AV_FILE_LIST** option users can configure a custom list of products to hunt for.
By default hunting for the following products is supported:

LuLu
BlockBlock
DoNotDisturb
ReiKey
RansomWhere
OverSight
CrowdStrike
Jamf
Netskope
Qualys
BitDefender
Symantec

## Verification Steps
1) Start msfconsole
2) Obtain a shell on an OSX device
3) Do: `use post/osx/gather/antivirus_hunter`
4) Do: `set session #`
5) ** Optional ** Do: `set AV_FILE_LIST <file>`
6) Do: `run`
7) Will be returned a list of process names

## Options

 ### AV_FILE_LIST

The AV_FILE_LIST option speciifies a file path which will hold a file containing a list of additional security products to
hunt for. Each item within this file should be separated with a new line character.

## Scenarios

### User level shell on Monetery

```
msf exploit(multi/handler) > use post/osx/gather/antivirus_hunter
msf post(osx/gather/antivirus_hunter) > set session 1
msf post(osx/gather/antivirus_hunter) > run
[*] Retrieving process list...
[*] Hunting processes for AV products...
[+] Found potential process artifact for LuLu: {"name"=>"LuLu", "pid"=>700}
[+] Found potential process artifact for BlockBlock: {"name"=>"BlockBlock Helpe", "pid"=>697}
[+] Found potential process artifact for BlockBlock: {"name"=>"BlockBlock", "pid"=>344}
[+] Found potential process artifact for Xprotect: {"name"=>"JAMF", "pid"=>36895}
[+] Found potential process artifact for Xprotect: {"name"=>"CrowdStrike Agent", "pid"=>35985}
[*] Post module execution completed
msf post(osx/gather/antivirus_hunter) > exit
```
