# Understanding Metasploit's Filesystem
The file system of Metasploit can be a little confusing at times. The following is a guide that should help 
to explain some of the common folders that you might use. Keep in mind that on Kali Linux your root install directory
will likely be `/usr/share/metasploit-framework`. For Omnibus installers downloaded from https://downloads.metasploit.com/
or a similar location, it will be `/opt/metasploit` on Linux devices, or `C:\metasploit-framework` or `D:\metasploit-framework`
by default for Windows devices.

The following are some of the most important folders. Note this isn't a complete list, but should help you get acquainted
with the file system of Metasploit for most use cases.

## app
This directory contains ActiveRecord concerns, models and validators.

## config
Contains various files that help configure Metasploit. Most files here you'll never have to deal with, though 
`database.yml.example` might be useful for those looking to configure their database, and `openssl.conf` 
might be helpful for those trying to troubleshoot OpenSSL issues in Metasploit.

## data
This folder contains various data files used for a variety of purposes, including but not limited to banners for the
console, exploit source code for exploits (under `data/exploits`), template code and binaries, wordlists and shellcode.

As a general rule of thumb this folder will most often be used when you are using compiled binaries or source code from
other exploits for cases such as local privilege escalation exploits and need to provide the exploit code and compiled 
binaries so that maintainers can verify the binary and compile it themselves, as so that modules can find the R7 compiled
version of the resulting binary for use during exploitation.

## db
Contains `modules_metadata_base.json` which contains information about all modules within Metasploit, as well as 
`schema.rb` which describes current state of the database schema maintained by Rails ActiveRecord.

## docker
Contains files related to running Metasploit inside Docker.

## docs
This contains all the documentation files that are on https://docs.metasploit.com as well as the associated server files
so that you can run a local copy of this site offline.

## documentation
This folder is primarily used to hold documentation for Metasploit's various modules, as well as the developers guide
at `developers_guide.pdf`.

## external
This folder contains files to assist in using Metasploit with other tools such as `burp-proxy`, `vscode` and `zsh`.
It also contains `serialport`, which is a Rapid7 fork of the original `ruby-serialport` project provided by
RubyForge.org. Most importantly though, it contains the `source` directory, which contains source code for all
compiled binaries in Metasploit Framework so that users can verify the code being used.

## kubernetes
Contains files related to deploying Metasploit in Kubernetes for Kubernetes testing, using a `meterpreter` helm chart.

## lib
This is where all of the libraries and mixins of Metasploit live. Generally speaking any code that will be reused
across multiple modules will be placed into a library or mixin which will then be placed under this folder.

## modules
This is the folder where all of Metasploit's modules live. These modules are scripts in Ruby that interface with
Metasploit itself to perform some specific task. There are various types of modules, such as `exploit` modules to
exploit a vulnerability and gain a shell, `auxiliary` to perform a non-shell gaining activity, `payloads` for
Metasploit's various payloads (which are also modules), and `post` for post exploitation modules.

## plugins
This is where plugins for Metasploit live, which allow Metasploit to interface with other tools and services.

## script
This contains the `rails.rb` file which will automatically be run when the command `rails` is run from
the root of Metasploit itself, and allows Rails to populate its list of additional commands
that are available for users to use.

## scripts
This folder contains all resource, shell, and Meterpreter scripts in Metasploit. Note that Metasploit no longer supports
Meterpreter scripts, so the `meterpreter/` folder should be treated as deprecated and is likely to be removed in the 
future.

## spec
All RSpec related unit test files reside under this directory.

## test
Contains files related to integration tests for things such as payload testing,
modules used in sanity testing, as well as tests that can be exercised using
https://github.com/rapid7/geppetto.

## tools
This folder contains standalone scripts that can help developers and users with various tasks, such as `msftidy.rb`
which checks modules to make sure they conform to our linting rules, and `msftidy_docs.rb` which does the same for
documentation files.