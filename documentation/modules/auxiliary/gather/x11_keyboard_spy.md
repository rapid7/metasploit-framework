## Vulnerable Application

This module binds to an open X11 host to log keystrokes. The X11 service can accept
connections from any users when misconfigured with the command `xhost +`.
This module is a close copy of the old xspy c program which has been on Kali for a long time.
The module works by connecting to the X11 session, creating a background
window, binding a keyboard to it and creating a notification alert when a key
is pressed.

One of the major limitations of xspy, and thus this module, is that it polls
at a very fast rate. Faster than a key being pressed is released (especially before
the repeat delay is hit). To combat printing multiple characters for a single key
press, repeat characters are ignored.

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
4. `socat -d -d TCP-LISTEN:6000,fork,bind=<IP to listen to here> UNIX-CONNECT:/tmp/.X11-unix/X0`

## Verification Steps
Example steps in this format (is also in the PR):

1. Install the application
1. Start msfconsole
1. Do: `use [module path]`
1. Do: `run`
1. You should get a shell.

## Options
List each option and how to use it.

### Option Name

Talk about what it does, and how to use it appropriately. If the default value is likely to change, include the default value here.

## Scenarios
Specific demo of using the module that might be useful in a real world scenario.

### Version and OS

```
code or console output
```

For example:

To do this specific thing, here's how you do it:

```
msf > use module_name
msf auxiliary(module_name) > set POWERLEVEL >9000
msf auxiliary(module_name) > exploit
```

## Confirming

To keylog the remote host, we use a tool called [xspy](http://tools.kali.org/sniffingspoofing/xspy)