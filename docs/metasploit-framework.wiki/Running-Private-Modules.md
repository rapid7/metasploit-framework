If you're in the business of writing or collecting Metasploit modules that aren't part of the standard distribution, then you need a convenient way to load those modules in Metasploit. Never fear, it's pretty easy, using Metasploit's default local module search path, `$HOME/.msf4/modules`, and there are just a couple caveats:

## Mirror the "real" Metasploit module paths

You must first set up a directory structure that fits with Metasploit's expectations of path names. What this typically means is that you should first create an "exploits" directory structure, like so:

```bash
mkdir -p $HOME/.msf4/modules/exploits
```

If you are using `auxiliary` or `post` modules, or are writing `payloads` you'll want to `mkdir` those as well.

## Create an appropriate category

Modules are sorted by (somewhat arbitrary) categories. These can be anything you like; I usually use `test` or `private`, but if you are developing a module with an eye toward providing it to the main Metasploit distribution, you will want to mirror the real module path. For example:

```bash
mkdir -p $HOME/.msf4/modules/exploits/windows/fileformat
```

... if you are developing a file format exploit for Windows.

## Create the module

Once you have a directory to place it in, feel free to download or start writing your module.

## Using Python/Go modules

External modules, most commonly written in Python/Go, need to additionally be marked as executable in order to be loaded by Metasploit.

For full details:
- [[Writing External Python Modules]]
- [[Writing External GoLang Modules]]

## Test it all out

If you already have msfconsole running, use a `reload_all` command to pick up your new modules. If not, just start msfconsole and they'll be picked up automatically. If you'd like to test with something generic, I have a module posted up as a gist, here: <https://gist.github.com/todb-r7/5935519>, so let's give it a shot:

```bash
mkdir -p $HOME/.msf4/modules/exploits/test
curl -Lo ~/.msf4/modules/exploits/test/test_module.rb https://gist.github.com/todb-r7/5935519/raw/17f7e40ab9054051c1f7e0655c6f8c8a1787d4f5/test_module.rb
todb@ubuntu:~$ mkdir -p $HOME/.msf4/modules/exploits/test
todb@ubuntu:~$ curl -Lo ~/.msf4/modules/exploits/test/test_module.rb https://gist.github.com/todb-r7/5935519/raw/6e5d2da61c82b0aa8cec36825363118e9dd5f86b/test_module.rb
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1140    0  1140    0     0   3607      0 --:--:-- --:--:-- --:--:--  7808
```

Then, in my msfconsole window:

```msf
msf > reload_all
[*] Reloading modules from all module paths...
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v4.6.2-2013052901 [core:4.6 api:1.0]
+ -- --=[ 1122 exploits - 707 auxiliary - 192 post
+ -- --=[ 307 payloads - 30 encoders - 8 nops

msf > use exploit/test/test_module
msf exploit(test_module) > info

       Name: Fake Test Module
     Module: exploit/test/test_module
    Version: 0
   Platform: Windows
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent

Provided by:
  todb <todb@metasploit.com>

Available targets:
  Id  Name
  --  ----
  0   Universal

Basic options:
  Name  Current Setting  Required  Description
  ----  ---------------  --------  -----------
  DATA  Hello, world!    yes       The output data

Payload information:

Description:
  If this module loads, you know you're doing it right.

References:
  https://cvedetails.com/cve/1970-0001/

msf exploit(test_module) > exploit

[*] Started reverse handler on 192.168.145.1:4444
[+] Hello, world!
msf exploit(test_module) >
```

## Troubleshooting

That's really all there is to it. The most common problems that people (including myself) run into are:

* Attempting to create a module in `$HOME/.msf4/modules/`. This won't work because you need to specify if it's an exploit or a payload or something. Check `ls /opt/metasploit/apps/pro/msf3/modules/` (or where your install of Metasploit lives).
* Attempting to create a module in `$HOME/.msf4/modules/auxiliary/`. This won't work because you need at least one level of categorization. It can be new, like `auxiliary/0day/`, or existing, like `auxiliary/scanner/scada/`.
* Attempting to create a module in `$HOME/.msf4/exploit/` or `$HOME/.msf4/posts/`. Note the pluralization of the directory names; they're different for different things. Exploits, payloads, encoders, and nops are plural, while auxiliary and post are singular.

### Metasploit Pro

Note that the `$HOME` directory for Metasploit Community Edition is going to be `root` and not your own user directory, so if you are expecting modules to show up in the Metasploit Pro web UIs, you will want to stash your external modules in `/root/.msf4/modules`. Of course, this means you need root access to the machine in question, but hey, you're a l33t Metasploit user, so that shouldn't be too hard.

Also note that if your modules are not displaying in the web UI, you should restart Pro service.

### Windows

For Windows users, the above is all true, except for accessing the modules from the web GUI. Sadly, you're a little out of luck; the module load paths on Windows are a little more restrictive and don't allow for external modules. However, the Console2-based Metasploit Console (Start > Programs > Metasploit > Metasploit Console) will work out just fine.

### New mixins and protocols

Any module that requires on changes to core library functions, such as new protocol parsers or other library mixins, aren't going to work out for you this way -- you're going to end up spewing errors all over the place as your module tries to load these classes. It's possible to write modules as completely self-contained in nearly all cases (thanks to Ruby's open class architecture), but such modules nearly always get refactored later to make the protocol and other mixin bits available to other modules.

In this case, it would be better to work with modules like that using a proper GitHub checkout with a development branch -- see the [[dev environment setup docs|./dev/Setting-Up-a-Metasploit-Development-Environment.md]] for tons more on that.

## A final warning

If you are loading new and exciting Metasploit modules, know that these things will tend to have access to anything you have access to; doubly so if you're dropping them in root. Metasploit modules are plain text Ruby, so you can read them -- but please be careful, and only add external modules from trusted sources; don't just go grabbing any old thing you see on the Internet, because you may find yourself backdoored (or worse) in short order.
