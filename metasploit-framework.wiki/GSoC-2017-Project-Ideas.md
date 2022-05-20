GSoC Project Ideas in no particular order. When you've picked one, take a look at [[GSoC 2017 Student Proposal]] for how to make a proposal.


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
1. A new command dispatcher implementing at least these commands: `upload`, `download`, `ls`, `cd`
1. We'll need to modify `auxiliary/scanner/ftp/ftp_login` to create one of these awesome new sessions when authentication is successful.

**Difficulty**: 2/5
**Requirements**: Ruby

### SMB-based file transport for Meterpreter

The idea here is to create a transport that allows Meterpreter and Console to talk via File handles opened via UNC path. In cases where 445 is allowed outbound, Meterpreter can open file handles to a UNC path that MSF is listening on, and they can communicate on those file handles. For this to work we need:

1. A new transport that knows how to operate over SMB file handles
   * In particular, one file handle is used for writing, and one for reading.
1. New stagers that use the Win32 API to open file handles to a given UNC path.
  * Most of this is already done in a PR for named pipe transport support, and so a few changes to those stagers should result in it working fine for this.
1. To come up with a method/protocol that both Console and Meterpreter can use to identify when new sessions come in.

Given that SMB file reading and writing is already a thing, this shouldn't be too hard on the MSF side.

**Difficulty**: 3/5
**Requirements**: Ruby & SMB
**Mentor**: [@OJ](https://github.com/oj) and/or [@egypt](https://github.com/egypt)

--

# Payload side

### Malleable HTTP/S C2 for Meterpreter

Currently, the attributes that one can set for how a Meterpreter payload appears at the HTTP level are limited. We would like the ability to set and add arbitrary HTTP headers to requests and responses, so that the traffic appears more realistic.

**Difficulty**: 5/5
**Requirements**: C, Ruby. Bonus: Python, PHP
**Mentor**: [@busterb](https://github.com/busterb)

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

### SMB-based file transport for Meterpreter

This is the Meterpreter side of the SMB transport mentioned in the Console section. For this to work we need:

1. A new Meterpreter transport that uses file handles to read and write data over SMB to talk to MSF.
    * Use the named pipe transport PR to see how this might work.
1. Full support of the "protocol" that has been designed so that MSF knows when sessions come in.

**Difficulty**: 2/5
**Requirements**: C, Windows systems programming
**Mentor**: [@OJ](https://github.com/oj)

--

# Metasploitable3

[Metasploitable3](https://github.com/rapid7/metasploitable3) is an
intentionally vulnerable virtual machine. It was created to be a
learning tool for new users as well as a place to test Metasploit and
its payloads.

### Linux: add vulnerabilities

**Requirements**: Vagrant

### Windows: add vulnerabilities

**Requirements**: Vagrant


--

# Miscellaneous

### Replace `msftidy` with a real linter

[Our current module style checker](https://github.com/rapid7/metasploit-framework/blob/master/tools/dev/msftidy.rb) is a mass of regular expressions attempting to look for bad patterns. It could be much improved by using a real lexer. We could use rubocop as a base for this.

This could also dovetail into an ongoing documentation project.

**Difficulty**: 2/5
**Requirements**: Ruby



# Potential Mentors

All of the following folks have expressed willingness to be mentors.

* [@busterb](https://github.com/busterb)
* [@egypt](https://github.com/egypt)
* [@hdm](https://github.com/hdm)
* [@jhart-r7](https://github.com/jhart-r7)
* [@jinq102030](https://github.com/jinq102030)
* [@mubix](https://github.com/mubix)
* [@OJ](https://github.com/oj)
* [@sempervictus](https://github.com/sempervictus)
* [@wvu](https://github.com/wvu-r7)
* [@zeroSteiner](https://github.com/zeroSteiner)
