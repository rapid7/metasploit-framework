Post module development is a challenge to your programming skills. It's not like writing a memory corruption based exploit, where technically speaking is usually about crafting a malicious input - a string. A post module is more about proper module design, practical knowledge in Ruby and the Metasploit library. It's also a very valuable skill to have, because if you don't know what to do after popping a shell, what's the point of the penetration test, right? Also, what if a module doesn't work? Are you willing to wait days, weeks, or maybe even months for someone else to fix it for you? Probably not. If you know how to do it yourself, you can probably fix it a lot sooner, and continue with your pentest and do more things. So learn post module development! It's good for you, and your career.

## Plan your module

Just like writing a software, before you start coding you should have a clear and specific goal for what your post module does. It's never a good idea to have multiple functionalities in a single module. For example: having it steal the network configuration files, steal passwd, hashes, shell history, etc. Instead, you should break it down into multiple modules.

You should also think about what session types to support: meterpreter, or shell. Ideally, support both. But if you have to choose between the two, on Windows you should favor Windows Meterpreter. On Linux, the shell session type has been a stronger candidate than the Linux Meterpreter, but hopefully this will change in the near future. For platforms that don't have a Meterpreter, obviously your only choice is a shell.

Another important thing is to think about how your module will perform on different distributions/systems. For example, say you want to run a ```ifconfig``` command on Linux. On Ubuntu it's a no-brainer, simply run the ```ifconfig``` command. Well, a different Linux distro might not actually know what you're asking, so you have to be more specific and do ```/sbin/ifconfig``` instead. Same thing with Windows. Is it ```C:\WINDOWS\``` or ```C:\WinNT```? It's both. Is it ```C:\Documents and Settings\[User name]```, or ```C:\Users\[User name]```? Both, depends on that Windows version. A better solution to that would be use an environment variable :-)

Always do your homework, and contain as many scenarios you can think of. And most importantly, get your VMs and TEST!

### Categories of post modules

Post modules are categorized based on their behavior. For example, if it collects data, naturally it goes to the "gather" category. If it adds/updates/or removes an user, it belongs to "manage". Here's a list as a reference:

| Category | Description |
| -------- | ----------- |
| **gather** | Modules that involve data gathering/collecting/enumeration. |
| **gather/credentials** | Modules that steal credentials. |
| **gather/forensics** | Modules that involve forensics data gathering. |
| **manage** | Modules that modifies/operates/manipulates something on the system. Session management related tasks such as migration, injection also go here. |
| **recon** | Modules that will help you learn more about the system in terms of reconnaissance, but not about data stealing. Understand this is not the same as "gather" type modules. |
| **wlan** | Modules that are for WLAN related tasks. |
| **escalate** | This is deprecated, but the modules remain there due to popularity. This used to be the place for privilege escalation modules. All privilege escalation modules are no longer considered as post modules, they're now exploits. |
| **capture** | Modules that involve monitoring something for data collection. For example: key logging. |


### Session object

So you know how in Lord of the Rings, people are totally obsessed with the One Ring? Well, that's how it is with the session object. The one object you cannot live without, it's your precious. All post modules and other related mixins basically are built on top of the session object, because it knows everything about the compromised host, and allows you to command it.

You can use the ```session``` method to access the session object, or its alias ```client```. The best way to interact with one is via irb, here's an example of how:

```msf
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

One commonly used method of the session object is the `platform` method. For example, if you're writing a post module for a windows exploit, in the check method you'll likely want to use `session.platform` to ensure the target session is affected:
```ruby
    unless session.platform == 'windows'
      # Non-Windows systems are definitely not affected.
      return Exploit::CheckCode::Safe
    end
```

You can also look at [other current post modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post) and see how they use their session object.

### The Msf::Post Mixin

As we explained, most post module mixins are built on top of the session object, and there are many out there. However, there is a main one you obviously cannot live without: the ```Msf::Post``` mixin. When you create a post module with this mixin, a lot of other mixins are also already included for all kinds of scenarios, to be more specific:

* **[msf/core/post/common](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/post/common.rb)** - Common methods post modules use, for example: ```cmd_exec```.
* **[msf/core/post_mixin](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/post_mixin.rb)** - Keeps track of the session state.
* **[msf/core/post/file](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/post/file.rb)** - File system related methods.
* **[msf/core/post/webrtc](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/post/webrtc.rb)** - Uses WebRTC to interact with the target machine's webcam.
* **[msf/core/post/linux](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/post/linux)** - There actually isn't a lot going on, just ```get_sysinfo``` and ```is_root?``` specifically for Linux.
* **[msf/core/post/osx](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/post/osx)** - ```get_sysinfo```, ```get_users```, ```get_system_accounts```, ```get_groups```, and methods for operating the target machine's webcam.
* **[msf/core/post/solaris](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/post/solaris)** - Pretty much like the linux mixin. Same methods, but for Solaris.
* **[msf/core/post/unix](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/post/unix.rb)** - ```get_users```, ```get_groups```, ```enum_user_directories```
* **[msf/core/post/windows](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/post/windows)** - Most of the development time are spent here. From Windows account management, event log, file info, Railgun, LDAP, netapi, powershell, registry, wmic, services, etc.

### Template

Here we have a post module template. As you can see, there are some required fields that need to be filled. We'll explain each:

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '[Platform] [Module Category] [Software] [Function]',
        'Description' => %q{
          Say something that the user might want to know.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Name' ],
        'Platform' => [ 'win', 'linux', 'osx', 'unix', 'bsd', 'solaris' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    )
  end

  def run
    # Main method
  end
end
```

The **Name** field should begin with a platform, such as: Multi, Windows, Linux, OS X, etc. Followed by the module's category, such as: Gather, Manage, Recon, Capture, Wlan. Followed by the name of the software, and then finally a few words that describe the functionality of the module. A naming example: "Multi Gather RndFTP Credential Enumeration".

The **Description** field should explain what the module does, things to watch out for, specific requirements, the more the better. The goal is to let the user understand what he's using without the need to actually read the module's source and figure things out. And trust me, most of them don't.

The **Author** field is where you put your name. The format should be "Name <email>". If you want to have your Twitter handle there, leave it as a comment, for example: "Name <email> # handle"

The **Platform** field indicates what platforms are supported, for example: win, linux, osx, unix, bsd.

The **SessionTypes** field should be either meterpreter, or shell. You should try to support both.

And finally, the ```run``` method is like your main method. Start writing your code there.

### Basic git commands

Metasploit no longer uses svn for source code management, instead we use git, so knowing some tricks with git go a long way. We're not here to lecture you about how awesome git is, we know it has a learning curve and it's not surprising to find new users making mistakes. Every once a while, your git "rage" will kick in, and we understand. However, it's important for you to take advantage of branching.

Every time you make a module, or make some changes to existing code, you should not do so on the default master branch. Why? Because when you do a ```msfupdate```, which is Metasploit's utility for updating your repository, it will do a git reset before merging the changes, and all your code go bye-bye.

Another mistake people tend to do is have all the changes on `master` before submitting a pull request. This is a bad idea, because most likely you're submitting other crap you don't intend to change, and/or you're probably asking us to merge other unnecessary commit history when there only needs to be one commit. Thanks for contributing your module to the community, but no thanks to your crazy commit history.

So as a habit, when you want to make something new, or change something, begin with a new branch that's up to date to master. First off, make sure you're on master. If you do a ```git status``` it will tell you what branch you're currently on:

```
$ git status
# On branch upstream-master
nothing to commit, working directory clean
```

Ok, now do a ```git pull``` to download the latest changes from Metasploit:

```
$ git pull
Already up-to-date.
```

At this point, you're ready to start a new branch. In this case, we'll name our new branch "my_awesome_branch":

```
$ git checkout -b my_awesome_module
Switched to a new branch 'my_awesome_module'
```

And then you can go ahead and add that module. Make sure it's in the appropriate path:

```
$ git add [module path]
```

When you decide to save the changes, commit (if there's only one module, you can do ```git commit -a``` too so you don't have to type the module path. Note ```-a``` really means EVERYTHING):

```
$ git commit [module path]
```

When you're done, push your changes, which will upload your code to your remote branch "my_awesome_branch". You must push your changes in order to submit the pull request, or share it with others on the Internet.

```
$ git push origin my_awesome_branch
```

### References

- <https://github.com/rapid7/metasploit-framework/tree/master/modules/post>
- <https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/post>
