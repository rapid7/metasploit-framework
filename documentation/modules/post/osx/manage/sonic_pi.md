## Intro

This module controls Sonic Pi via its local OSC server.

The server runs on `127.0.0.1:4557` and receives OSC messages over UDP.

## Setup

I've supported only OS X. I had no luck running Sonic Pi on Windows, and
I can't test Raspberry Pi at the moment.

`brew cask install sonic-pi` if you have Homebrew or download and
install Sonic Pi from <https://sonic-pi.net/#mac>.

## Actions

```
Name  Description
----  -----------
Run   Run Sonic Pi code
Stop  Stop all jobs
```

## Options

**OSC_HOST**

This is the OSC server host, which is `127.0.0.1` by default.

**OSC_PORT**

This is the OSC server (UDP) port, which is `4557` by default.

**START_SONIC_PI**

Enable this to start Sonic Pi if it isn't running already. Note that
this will start the GUI, which will be visible to the user.

**FILE**

This is the path to Sonic Pi code you want to run. It can be arbitrary
Ruby.

**SonicPiPath**

This is the path to the Sonic Pi executable within its application
bundle.

**RubyPath**

This is the path to a Ruby executable. Sonic Pi's vendored Ruby is the
default.

## Usage

```
msf5 post(osx/manage/sonic_pi) > options

Module options (post/osx/manage/sonic_pi):

   Name            Current Setting                                             Required  Description
   ----            ---------------                                             --------  -----------
   FILE            /rapid7/metasploit-framework/data/post/sonic_pi_example.rb  yes       Path to Sonic Pi code
   OSC_HOST        127.0.0.1                                                   yes       OSC server host
   OSC_PORT        4557                                                        yes       OSC server port
   SESSION                                                                     yes       The session to run this module on.
   START_SONIC_PI  false                                                       yes       Start Sonic Pi


Post action:

   Name  Description
   ----  -----------
   Run   Run Sonic Pi code


msf5 post(osx/manage/sonic_pi) > advanced

Module advanced options (post/osx/manage/sonic_pi):

   Name         Current Setting                                         Required  Description
   ----         ---------------                                         --------  -----------
   RubyPath     /Applications/Sonic Pi.app/server/native/ruby/bin/ruby  yes       Path to Ruby executable
   SonicPiPath  /Applications/Sonic Pi.app/Contents/MacOS/Sonic Pi      yes       Path to Sonic Pi executable
   VERBOSE      true                                                    no        Enable detailed status messages
   WORKSPACE                                                            no        Specify the workspace for this module

msf5 post(osx/manage/sonic_pi) > show actions

Post actions:

   Name  Description
   ----  -----------
   Run   Run Sonic Pi code
   Stop  Stop all jobs


msf5 post(osx/manage/sonic_pi) > set session -1
session => -1
msf5 post(osx/manage/sonic_pi) > run

[+] Sonic Pi is running
[*] Running Sonic Pi code: /rapid7/metasploit-framework/data/post/sonic_pi_example.rb
[*] echo [snip] | base64 -D | /Applications/Sonic\ Pi.app/server/native/ruby/bin/ruby
[*] Post module execution completed
msf5 post(osx/manage/sonic_pi) > set action Stop
action => Stop
msf5 post(osx/manage/sonic_pi) > run

[+] Sonic Pi is running
[*] Stopping all jobs
[*] echo [snip] | base64 -D | /Applications/Sonic\ Pi.app/server/native/ruby/bin/ruby
[*] Post module execution completed
msf5 post(osx/manage/sonic_pi) >
```
