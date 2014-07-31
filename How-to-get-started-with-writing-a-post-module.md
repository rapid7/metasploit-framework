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

### The Msf::Post Mixin

There are many mixins out there in Metasploit that you can use for post-exploitation, but there is one thing you obviously cannot live without: the ```Msf::Post``` mixin. When you create a post module with this mixin, a lot of other mixins are also already added automatically for all kinds of scenarios, to be more specific:

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

### Templates

a few of these should do the trick.

### References

Links. Tons of them.