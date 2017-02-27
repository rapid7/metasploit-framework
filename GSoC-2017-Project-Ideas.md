GSoC Project Ideas in no particular order.


### Submit your own

If you want to suggest your own idea, please discuss it with us first on [our mailing list](https://groups.google.com/forum/#!forum/metasploit-hackers) to make sure it is a reasonable amount of work for a summer and that it fits the goals of the project.


### Convert between `CMD_UNIX` and the interpreted language architectures

Perl, Python, and Ruby scripts can all be run via a short command line invocation. It would be nice to be able to use these payloads in `ARCH_CMD` contexts as well as their own separate architectures (`ARCH_PYTHON`, `ARCH_RUBY`). This would allow modules that exploit command injection vulnerabilities to use python meterpreter in particular.

**Requirements**: Ruby, Python, bash/sh


### Automated exploit reliability scoring

Automatically run a module over and over, determine success rates.

**Mentor**: [@busterb](https://github.com/busterb)


### Exploit regression testing

Set up automated testing using something like Vagrant to spin up and configure vulnerable machines, run exploits against them.


### A categorical focus

Something like "make all X exploits badass", or add a full suite of modules around particular gear or vendor stack.

**Mentor**: [@hdm](https://github.com/hdm)


### Allow post modules to take a payload

And then move the `exploit/*/local` modules that aren't actually exploits back to `post/`


### SMB2 support

(see also [ruby_smb project](https://github.com/rapid7/ruby_smb))

**Mentor**:  [@egypt](https://github.com/egypt)

--

# Payload side

### Malleable HTTP/S C2 for Meterpreter

Currently, the attributes that one can set for how a Meterpreter payload appears at the HTTP level are limited. We would like the ability to set and add arbitrary HTTP headers to requests and responses, so that the traffic appears more realistic.

**Requirements**: C, Ruby. Bonus: Python, PHP

**Mentor**: [@busterb](https://github.com/busterb)


### Gossip protocol for payload communications

Allow meterpreter to act as a mesh network inside a corporate environment.

**Requirements**: C, network protocol design. Bonus: Python, PHP


### Asynchronous victim-side scripting

Using either Python or Powershell (or maybe both if it can be abstract enough). This could allow things like running Responder.py or Empire on a compromised host.

**Requirements**: C, Python/Powershell

**Mentor**: [@OJ](https://github.com/oj)

### Use SChannel in native Windows Meterpreter instead of embedded OpenSSL

[SChannel](https://msdn.microsoft.com/en-us/library/windows/desktop/ms678421(v=vs.85).aspx) is Windows' built-in TLS library.

**Requirements**: C

**Mentor**: [@OJ](https://github.com/oj)

--

# Metasploitable3

### Linux: add vulnerabilities

**Requirements**: Vagrant

### Windows: add vulnerabilities

**Requirements**: Vagrant


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
* [@wvu](https://github.com/wvu-r7)
* [@zeroSteiner](https://github.com/zeroSteiner)