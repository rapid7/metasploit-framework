# Metasploit Payloads

This gem is a Metasploit-specific gem that contains all of the
Meterpreter payloads (except for Mettle). This is made up of:

* Windows DLLs
* Java Classes
* PHP/Python Scripts

Mettle, the Native Linux / Posix payload, currently is developed at
https://github.com/rapid7/mettle (to be moved here at some point?)

## Installation

Given the nature of the contents of this gem, installation
outside of Metasploit is not advised. To use Meterpreter,
download and install Metasploit itself.

## Building

To build the gem:

1. Update the version number in `lib/metasploit-payloads/version.rb`
1. Run:
  - `rake win_prep` to build on Windows
  - `rake java_prep` to build Java files
  - `rake python_prep` and `rake php_prep` to copy the latest PHP/Python
    meterpreter files into place
1. Binaries will be built in the `data` folder.
1. Run `rake build` to generate the new gem file using content in
   meterpreter folder.
1. Run `rake release` to release the binary to RubyGems.

Note, when using the command `rake win_prep` and related Windows rake
tasks, you must be in the Visual Studio Developer command prompt,
**and** have a path to a git binary in your default path. If your
git.exe is part of posh-git or GitHub for Windows, that means adding
something like the following to your path:

`"C:\Users\USERNAME\AppData\Local\GitHub\PortableGit_LONG_UUID_STRING_THING\bin"`

