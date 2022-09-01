## Vulnerable Application

KOFFEE exploits the CVE-2020-8539, which is an Arbitrary Code Execution vulnerability that allows a user to execute the
`micomd` binary with valid payloads on Kia Motors Head Units. By using KOFFEE an attacker can send crafted `micomd`
commands to control the head unit and send CAN bus frames into the Multimedia CAN (M-Can) of the vehicle.

### Vulnerable Head Unit software versions
- SOP.003.30.180703
- SOP.005.7.181019
- SOP.007.1.191209

## Verification Steps

- [ ] Start `msfconsole`
- [ ] `use post/android/local/koffee`
- [ ] `set session 1`
- [ ] `toogle_radio_mute` or `run`

### What do you need
* An active session with the Head Unit

## Options

### MICOMD
It contains the path to micomd executable

### NUM_MSG
It expresses the number of MICOM commands sent each time

### PERIOD
It indicates the time (ms) interval between two MICOM commands, aka Period of CAN frames

### SESSION
It refers to the metasploit session number on which this module is run.

### CMD_PAYLOAD
It refers to the Micom payload to be injected, e.g., cmd byte1 byte3 byte2'. By default it is set to `00 00 00`. This
options works only for the `INJECT_CUSTOM` action

## Actions

The following actions can be triggered on the Head Unit. An action can be triggered by inserting in the Metasploit input
console the action name in lowercase, e.g., `camera_reverse_off`.

- CAMERA_REVERSE_OFF:          It hides the parking camera video stream
- CAMERA_REVERSE_ON:           It shows the parking camera video stream
- CLUSTER_CHANGE_LANGUAGE:     It changes the cluster language
- CLUSTER_RADIO_INFO:          It shows radio info in the instrument cluster
- CLUSTER_RANDOM_NAVIGATION:   It shows navigation signals in the instrument cluster
- CLUSTER_ROUNDABOUT_FARAWAY:  It shows a round about signal with variable distance in the instrument cluster
- CLUSTER_SPEED_LIMIT:         It changes the speed limit shown in the instrument cluster
- HIGH_SCREEN_BRIGHTNESS:      It increases the head unit screen brightness
- INJECT_CUSTOM:               It injects custom micom payloads
- LOW_FUEL_WARNING:            It pops up a low fuel message on the head unit
- LOW_SCREEN_BRIGHTNESS:       It decreases the head unit screen brightness
- MAX_RADIO_VOLUME:            It sets the radio volume to the max
- NAVIGATION_FULL_SCREEN:      It pops up the navigation app
- REDUCE_RADIO_VOLUME:         It reduces radio volume
- SEEK_DOWN_SEARCH:            It triggers the seek down radio frequency search
- SEEK_UP_SEARCH:              It triggers the seek up radio frequency search
- SET_NAVIGATION_ADDRESS:      It pops up the navigation address window
- SWITCH_OFF_Hu:               It switches off the head unit
- SWITCH_ON_Hu:                It switches on the head unit
- TOGGLE_RADIO_MUTE            It mutes/unmutes the radio

An action can be also triggered using the commands:
- [ ] `set action CAMERA_REVERSE_ON`
- [ ] `run`

To execute the `INJECT_CUSTOM` action, you may want also to set up the right payload.
The commands to use to trigger this action are
- [ ] `set action INJECT_CUSTOM`
- [ ] `set CMD_PAYLOAD 01 FF`
- [ ] `run`

## Scenarios
KOFFEE can be run as post-exploitation module when an active session is available with the Head Unit (HU). First, an
attacker may create a malicious apk to generate a remote connection with the HU. For instance, using msfvenom or other
tools, an attacker can create the malicious apk that, once installed in the HU, starts an active session. Now, the
attacker is able to use the KOFFEE exploit to take control of the HU and inject CAN bus frames into the M-CAN bus of the
vehicle.


### Usage

```
msf6 > use post/android/local/koffee
msf6 post(android/local/koffee) > set session 1
session => 1
msf6 post(android/local/koffee) > toggle_radio_mute

[*]  -- Starting action -- 
[*]  -- Mute/umute radio -- 
[+]  -- Command Sent -- 
```
