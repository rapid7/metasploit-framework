Metasploit is known for its free, open-source exploits - modules that pop shells. But in reality, penetration testers rely more on auxiliary modules, and often a successful pentest can be done without firing a single exploit. They're just more handy, and the punishment for a failed attempt is generally much lower. Professionals actually love auxiliary modules.

Another interesting fact about auxiliary modules is that some of them aren't so different from being exploits. The main difference is how it's defined in Metasploit: **if a module executes a payload, it's an exploit.** If not, even though it takes advantage of a vulnerability, it still belongs to the auxiliary category. If an auxiliary module is capable of running an Operating System command, it could be made into an exploit by delivering a `cmd*` payload and/or using a [[command stager|How-to-use-command-stagers]].

So you see, if you're an auxiliary module addict, you are on the right track.

## Plan your module

Just like writing a software, before you start coding you should have a clear and specific goal for what your auxiliary module does. It's never a good idea to have multiple functionalities in a single module. You should break it down into multiple modules instead.

You should also think about how your module will perform in different situations. For example, if it's meant to test against a Tomcat server, what happens if you use it against Nginx? Will it error out and leave a backtrace? If it does, you should handle that properly. Does your module require specific settings/conditions from the target machine? What happens if it doesn't? Will it error out again?

Most importantly, make sure to test your module thoroughly. It's always ugly to find out problems in the middle of an important engagement, that just might cost you.

## Main categories of auxiliary modules

Generally speaking, auxiliary modules are categorized based on their behavior, but this is somewhat inconsistent so you'll just have to use your best judgement and find the most appropriate one. Here's a list of the common ones:

| Category | Description |
| -------- | ----------- |
| **admin** | Modules that modify, operate, or manipulate something on target machine. |
| **analyze** | We initially created this folder for password-cracking modules that require analysis time. |
| **client** | We initially created this folder for an SMTP module for social-engineering purposes. |
| **dos** | Pretty self-explanatory: denial-of-service modules. |
| **fuzzers** | If your module is a fuzzer, this is where it belongs. Make sure to place it in the correct sub-directory based on the protocol. |
| **gather** | Modules that gather, collect, or enumerates data from a single target. |
| **scanner** | Modules that use the ```Msf::Auxiliary::Scanner``` mixin almost always go here. Make sure to place yours in the correct sub-directory based on the protocol. |
| **server** | Modules that are servers. |
| **sniffer** | Modules that are sniffers. |


There are actually a few more directories in auxiliary, but that's kind of where the gray area is. You are more than welcome to [see if yourself](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary).

## The Msf::Auxiliary::Scanner mixin

The ```Msf::Auxiliary::Scanner``` mixin is heavily used in auxiliary modules, so we might as well talk about it right here. The mixin allows you to be able to test against a range of hosts, and it's multi-threaded. To use it, first off you need to include the mixin under the scope of your ```Metasploit3``` class:

```ruby
include Msf::Auxiliary::Scanner
```

A couple of new things will be added to your module when you include this mixin. You will have a new datastore option named "RHOSTS", which allows the user to specify multiple hosts. There's a new "THREADS" option, which allows the number of threads to run during execution. There's also "ShowProgress" and "ShowProgressPercent" for tracking scan progress.

Typically, the main method for an auxiliary module is "def run". But when you use the ```Msf::Auxiliary::Scanenr``` mixin, you need to be using ```def run_host(ip)```. The IP parameter is the target machine.

## Templates

Here's the most basic example of an auxiliary module. We'll explain a bit more about the fields that need to be filled:

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Module name',
        'Description' => %q{
          Say something that the user might want to know.
        },
        'Author' => [ 'Name' ],
        'License' => MSF_LICENSE
      )
    )
  end

  def run
    # Main function
  end

end
```

The **Name** field can begin with the vendor name, but optional. Followed by the software name. And then a few words that basically describe what it's for. For example: "Dolibarr ERP/CRM Login Utility"

The **Description** field should explain what the module does, things to watch out for, specific requirements, the more the better. The goal is to let the user understand what he's using without the need to actually read the module's source and figure things out. And trust me, most of them don't.

The **Author** field is where you put your name. The format should be "Name ". If you want to have your Twitter handle there, leave it as a comment, for example: "Name # handle"

Because the ```Msf::Auxiliary::Scanner``` mixin is so popular, we figured you want a template for it, too. And here you go:

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Module name',
        'Description' => %q{
          Say something that the user might want to know.
        },
        'Author' => [ 'Name' ],
        'License' => MSF_LICENSE
      )
    )
  end

  def run_host(ip)
    # Main method
  end

end
```

### Basic git commands

Metasploit no longer uses svn for source code management, instead we use git, so knowing some tricks with git go a long way. We're not here to lecture you about how awesome git is, we know it has a learning curve and it's not surprising to find new users making mistakes. Every once a while, your git "rage" will kick in, and we understand. However, it's important for you to take advantage of branching.

Every time you make a module, or make some changes to existing code, you should not do so on the default master branch. Why? Because when you do a ```msfupdate```, which is Metasploit's utility for updating your repository, it will do a git reset before merging the changes, and all your code go bye-bye.

Another mistake people tend to do is have all the changes on master before submitting a pull request. This is a bad idea, because most likely you're submitting other crap you don't intend to change, and/or you're probably asking us to merge other unnecessary commit history when there only needs to be one commit. Thanks for contributing your module to the community, but no thanks to your crazy commit history.

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

## References

- <https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary>
- <https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/auxiliary.rb>
- <https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/auxiliary/scanner.rb>
