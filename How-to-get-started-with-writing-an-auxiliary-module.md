Metasploit is known for its free, open-source exploits - modules that pop shells. But in reality, penetration testers rely more on auxiliary modules, and often a successful pentest can be done without firing a single exploit. They're just more handy, and the punishment for a failed attempt is generally much lower. Professionals actually love auxiliary modules.

Another interesting fact about auxiliary modules is that some of them aren't so different from being exploits. The main difference is how it's defined in Metasploit: if a module pops a shell, it's an exploit. If not, even though it takes advantage of a vulnerability, it still belongs to the auxiliary category.

So you see, if you're an auxiliary module addict, you are on the right track.

### Plan your module

Just like writing a software, before you start coding you should have a clear and specific goal for what your auxiliary module does. It's never a good idea to have multiple functionalities in a single module. You should break it down into multiple modules instead.

You should also think about how your module will perform in different situations. For example, if it's meant to test against a Tomcat server, what happens if you use it against Nginx? Will it error out and leave a backtrace? If it does, you should handle that properly. Does your module require specific settings/conditions from the target machine? What happens if it doesn't? Will it error out again?

Most importantly, make sure to test your module thoroughly. It's always ugly to find out problems in the middle of an important engagement, that just might cost you.

### Main categories of auxiliary modules

Generally speaking, auxiliary modules are categorized based on their behavior, but this is somewhat inconsistent so you'll just have to use your best judgement and find the most appropriate one. Here's a list of the common ones:

* **admin** - Modules that modify, operate, or manipulate something on target machine.
* **analyze** - We initially created this folder for password-cracking modules that require analysis time.
* **client** - We initially created this folder for an SMTP module for social-engineering purposes.
* **crawler** - If you have a web-spider (crawler), put it here.
* **dos** - Pretty self-explanatory: denial-of-service modules.
* **fuzzers** - If your module is a fuzzer, this is where it belongs. Make sure to place it in the correct sub-directory based on the protocol.
* **gathers** - Modules that gather, collect, or enumerates data from a single target.
* **scanner** - Modules that use the ```Msf::Auxiliary::Scanner``` mixin almost always go here. Make sure to place yours in the correct sub-directory based on the protocol.
* **server** - Modules that are servers.
* **sniffer** - Modules that are sniffers.

There are actually a few more directories in auxiliary, but that's kind of where the gray area is. You are more than welcome to [see if yourself](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary).

### The Msf::Auxiliary::Scanner mixin

### Templates

### References