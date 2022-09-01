## Vulnerable Application

Finger is an older protocol which displays information about users on a machine.  This can be abused to verify if a user is valid on that machine.
The protocol itself was designed in the 1970s, and is run in cleartext.

The following was done on Kali linux:
  
  1. `apt-get install inetutils-inetd fingerd`
  2. Start the service: `/etc/init.d/inetutils-inetd start`

## Verification Steps

  1. Install fingerd
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/finger/finger_users`
  4. Do: `set rhosts`
  5. Do: `run`

## Options

**USERS_FILE**

The USERS_FILE is a newline delimited list of users and defaults to `unix_users.txt` included with metasploit.

## Scenarios

  A run against the configuration from these docs

  ```
    msf > use auxiliary/scanner/finger/finger_users
    msf auxiliary(finger_users) > set rhosts 127.0.0.1
    rhosts => 127.0.0.1
    msf auxiliary(finger_users) > run
    
    [+] 127.0.0.1:79          - 127.0.0.1:79 - Found user: root
    [+] 127.0.0.1:79          - 127.0.0.1:79 Users found: root
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

## Confirming using NMAP

Utilizing the [finger](https://nmap.org/nsedoc/scripts/finger.html) script

  ```
    # nmap -p 79 --script finger 127.0.0.1
    
    Starting Nmap 7.40 ( https://nmap.org ) at 2017-04-26 19:35 EDT
    Nmap scan report for localhost (127.0.0.1)
    Host is up (0.000039s latency).
    PORT   STATE SERVICE
    79/tcp open  finger
    | finger: Login     Name       Tty      Idle  Login Time   Office     Office Phone\x0D
    | root      root       tty2      16d  Apr 10 19:17 (:0)\x0D
    |_root      root      *pts/3      1d  Apr 25 19:11 (192.168.2.175)\x0D
    
    Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
  ```
