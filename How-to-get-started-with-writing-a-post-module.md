Post module development is a challenge to your programming skills. It's not like writing a memory corruption based exploit, where technically speaking is usually about crafting a malicious input - a string. A post module is more about proper module design, practical knowledge in Ruby and the Metasploit library. It's also a very valuable skill to have, because if you don't know what to do after popping a shell, what's the point of the penetration test, right? Also, what if a module doesn't work? Are you willing to wait days, weeks, or maybe even months for someone else to fix it for you? Probably not. If you know how to do it yourself, you can probably fix it a lot sooner, and continue with your pentest and do more things. So learn post module development! It's good for you, and your career.

## Plan your module

Just like writing a software, before you start coding you should have a clear and specific goal for what your post module does. It's never a good idea to have multiple functionalities in a single module. For example: having it steal the network configuration files, steal passwd, hashes, shell history, etc. Instead, you should break it down into multiple modules.

You should also think about what session types to support: meterpreter, or shell. Ideally, support both. But if you have to choose between the two, on Windows you should favor Windows Meterpreter. On Linux, the shell session type has been a stronger candidate than the Linux Meterpreter, but hopefully this will change in the near future. For platforms that don't have a Meterpreter, obviously your only choice is a shell.

Another important thing is to think about how your module will perform on different distributions/systems. For example, say you want to run a ```ifconfig``` command on Linux. On Ubuntu it's a no-brainer, simply run the ```ifconfig``` command. Well, a different Linux distro might not actually know what you're asking, so you have to be more specific and do ```/sbin/ifconfig``` instead. Same thing with Windows. Is it ```C:\WINDOWS\``` or ```C:\WinNT```? It's both. Is it ```C:\Documents and Settings\[User name]```, or ```C:\Users\User name```? Both, depends on that Windows version. A better solution to that would be use an environment variable :-)

Always do your homework, and contain as many scenarios you can think of. And most importantly, get your VMs and TEST!

### Categories of post modules

Post modules are categorized based on their behavior. For example, if it collects data, naturally it goes to the "gather" category. If it adds/updates/or removes an user, it belongs to "manage". Here's a list as a reference:

* **gather** - Modules that involve data gathering/collecting/enumeration.
* **gather/credentials** - Modules that steal credentials.
* **gather/forensics** - Modules that involve forensics data gathering.
* **manage** - Modules that modifies/operates/manipulates something on the system. Session management related tasks such as migration, injection also go here.
* **recon** - Modules that will help you learn more about the system in terms of reconnaissance, but not about data stealing. Understand this is not the same as "gather" type modules.
* **wlan** - Modules that are for WLAN related tasks.
* **escalate** - This is deprecated, but the modules remain there due to popularity. This used to be the place for privilege escalation modules. All privilege escalation modules are no longer considered as post modules, they're now exploits.
* **capture** - Modules that involve monitoring something for data collection. For example: key logging.

### Session object

So you know how in Lord of the Rings, people are totally obsessed with the One Ring? Well, that's how it is with the session object. The one object you cannot live without, it's your precious. All post modules and other related mixins basically are built on top of the session object, because it knows everything about the compromised host, and allows you to command it.

You can use the ```session``` method to access the session object, or its alias ```client```. The best way to interact with one is via irb, here's an example of how:

```
msf exploit(handler) > run

[*] Started reverse handler on 192.168.1.64:4444 
[*] Starting the payload handler...
[*] Sending stage (769536 bytes) to 192.168.1.106
[*] Meterpreter session 1 opened (192.168.1.64:4444 -> 192.168.1.106:55157) at 2014-07-31 17:59:36 -0500

meterpreter > irb
[*] Starting IRB shell
[*] The 'client' variable holds the meterpreter client

>> session.class
=> Msf::Sessions::Meterpreter_x86_Win
```

At this point you have the power to rule them all. But notice that the above example is a ```Msf::Sessions::Meterpreter_x86_Win``` object. There are actually several more different ones: command_shell.rb, meterpreter_php.rb, meterpreter_java.rb, meterpreter_x86_linux.rb, etc. Each behaves differently so it's actually kind of difficult to explain them all, but they are defined in the [lib/msf/base/sessions/](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/base/sessions) directory so you can see how they work. Or you can play with one since you're already in the irb prompt.

In Ruby, there are two object methods that are handy for debugging purposes.  The first is ```methods```, which will list all the public and protected methods from that object:

```ruby
session.methods
```

The other one is ```inspect```, which returns a string of a human-readable representation of the object:

```ruby
session.inspect
```

You can also look at [other current post modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post) and see how they use their session object.

### The Msf::Post Mixin

As we explained, most post module mixins are built on top of the session object, and there are many out there. However, there is a main one you obviously cannot live without: the ```Msf::Post``` mixin. When you create a post module with this mixin, a lot of other mixins are also already added automatically for all kinds of scenarios, to be more specific:

* **msf/core/post/common**
* **msf/core/post_mixin**
* **msf/core/post/file**
* **msf/core/post/webrtc**
* **msf/core/post/linux**
* **msf/core/post/osx**
* **msf/core/post/solaris**
* **msf/core/post/unix**
* **msf/core/post/windows**

### Data storage and reporting

### Basic git commands

### Template

One should do the trick, let your creativity take over.

```ruby
##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
        'Name'          => '[Platform] [Module Category] [Software] [Function]',
        'Description'   => %q{
          This awesome post module does something super rad and I cannot shut up about it.
          So I'm gonna do the best I can explain' what it does and how to use it, and
          hopefully my user will figure out how to use by just reading the description,
          without going through the code.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Name' ],
        'Platform'      => [ 'win', 'linux', 'osx', 'unix', 'bsd' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))
  end

  def run
    # Main function
  end

end
```

### References

Links. Tons of them.