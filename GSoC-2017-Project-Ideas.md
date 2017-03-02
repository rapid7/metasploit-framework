GSoC Project Ideas in no particular order.


### Submit your own

If you want to suggest your own idea, please discuss it with us first on [our mailing list](https://groups.google.com/forum/#!forum/metasploit-hackers) to make sure it is a reasonable amount of work for a summer and that it fits the goals of the project.

--

# Console side

### Convert between `CMD_UNIX` and the interpreted language architectures

Perl, Python, and Ruby scripts can all be run via a short command line invocation. It would be nice to be able to use these payloads in `ARCH_CMD` contexts as well as their own separate architectures (`ARCH_PYTHON`, `ARCH_RUBY`). This would allow modules that exploit command injection vulnerabilities to use python meterpreter in particular.

**Difficulty**: 4/5
**Requirements**: Ruby, Python, bash/sh
**Mentor**: [@wvu](https://github.com/wvu-r7) [@sempervictus](https://github.com/sempervictus)


### Automated exploit reliability scoring

Automatically run a module over and over, determine success rates.

**Mentor**: [@busterb](https://github.com/busterb)


### Exploit regression testing

Set up automated testing using something like Vagrant to spin up and configure vulnerable machines, run exploits against them.


### A categorical focus

Something like "make all X exploits badass", or add a full suite of modules around particular gear or vendor stack.


**Requirements**: Ruby
**Mentor**: [@hdm](https://github.com/hdm)


### Allow post modules to take a payload

As it stands, the framework defines anything that takes a payload to be an exploit. Because post-exploitation modules cannot take a payload, things that want to drop an executable for persistence are implemented as local exploits (in the `exploit/*/local` namespace instead of `post/*/persistence`). This project would give those kinds of modules a more consistent interface.

Once this is done, we can move the `exploit/*/local` modules that aren't actually exploits back to `post/`

**Difficulty**: 3/5
**Requirements**: Ruby
**Mentor**: [@egypt](https://github.com/egypt)


### SMB2 support

(see also [ruby_smb project](https://github.com/rapid7/ruby_smb))

**Difficulty**: 5/5
**Mentor**:  [@egypt](https://github.com/egypt)


### Filesystem sessions

The idea here is to create a new session type for authenticated protocols that give you filesystem access. The simplest is FTP, so that's where we should start. We'll need several pieces for this to work:

1. A new session interface in `Msf::Sessions` (`lib/msf/base/sessions/`). This should be abstract enough that we can implement protocols other than FTP in the future.
1. A mapping of protocol details to that interface.
1. A new command dispatcher implementing at least `upload`, `download`, `ls`, `cd` commands.
1. We'll need to modify `auxiliary/scanner/ftp/ftp_login` to create one of these awesome new sessions when authentication is successful.

**Difficulty**: 2/5
**Requirements**: Ruby

--

# Payload side

### Malleable HTTP/S C2 for Meterpreter

Currently, the attributes that one can set for how a Meterpreter payload appears at the HTTP level are limited. We would like the ability to set and add arbitrary HTTP headers to requests and responses, so that the traffic appears more realistic.

**Difficulty**: 5/5
**Requirements**: C, Ruby. Bonus: Python, PHP
**Mentor**: [@busterb](https://github.com/busterb)


### Gossip protocol for payload communications

Allow meterpreter to act as a mesh network inside a corporate environment.

**Difficulty**: 5/5
**Requirements**: C or Python, network protocol design. Bonus: PHP


### Asynchronous victim-side scripting

Using either Python or Powershell (or maybe both if it can be abstract enough). This could allow things like running Responder.py or Empire on a compromised host.

**Difficulty**: 4/5
**Requirements**: C, Python/Powershell
**Mentor**: [@OJ](https://github.com/oj)

### Use SChannel in native Windows Meterpreter instead of embedded OpenSSL

[SChannel](https://msdn.microsoft.com/en-us/library/windows/desktop/ms678421(v=vs.85).aspx) is Windows' built-in TLS library.

**Difficulty**: 3/5
**Requirements**: C, Windows systems programming
**Mentor**: [@OJ](https://github.com/oj)

--

# Metasploitable3

### Linux: add vulnerabilities

**Requirements**: Vagrant

### Windows: add vulnerabilities

**Requirements**: Vagrant


--

# Miscellaneous

Replace `msftidy` with a real linter using e.g. rubocop as a base.

**Difficulty**: 2/5
**Requirements**: Ruby

--


# Potential Mentors

All of the following folks have expressed willingness to be mentors.

* [@busterb](https://github.com/busterb)
* [@egypt](https://github.com/egypt)
* [@hdm](https://github.com/hdm)
* [@jhart](https://github.com/jhart)
* [@jinq102030](https://github.com/jinq102030)
* [@mubix](https://github.com/mubix)
* [@OJ](https://github.com/oj)
* [@sempervictus](https://github.com/sempervictus)
* [@wvu](https://github.com/wvu-r7)
* [@zeroSteiner](https://github.com/zeroSteiner)
