GSoC Project Ideas in no particular order.


### Submit your own

If you want to suggest your own idea, please discuss it with us first on [our mailing list](https://groups.google.com/forum/#!forum/metasploit-hackers) to make sure it is a reasonable amount of work for a summer and that it fits the goals of the project.


### Convert between cmd/unix/* and the various interpreted language architectures

Perl, Python, and Ruby scripts can all be run via a short command line invocation. It would be nice to be able to use these payloads in `ARCH_CMD` contexts as well as their own separate architectures (`ARCH_PYTHON`, `ARCH_RUBY`).

### Automated exploit reliability scoring

Automatically run a module over and over, determine success rates.

**Mentor**: [@busterb](https://github.com/busterb)

### Maleable HTTP/S C2 for Meterpreter

Currently, the attributes that one can set for how a Meterpreter payload appears at the HTTP level are limited. We would like the ability to set and add arbitrary HTTP headers to requests and responses, so that the traffic appears more realistic.

**Mentor**: [@busterb](https://github.com/busterb)

### Exploit regression testing

Set up automated testing using something like Vagrant to spin up and configure vulnerable machines, run exploits against them.

### A categorical focus

Something like "make all X exploits badass", or add a full suite of modules around particular gear or vendor stack.

**Mentor**: [@hdm](https://github.com/hdm)


### Allow post modules to take a payload

And then move the `exploit/*/local` modules that aren't actually exploits back to `post/` 


### SMB2 support

(see also https://github.com/rapid7/ruby_smb)

**Mentor**:  [@egypt](https://github.com/egypt)

--

# Payload side

### Gossip protocol for payload communications

Allow meterpreter to act as a mesh network inside a corporate environment.


### Asynchronous victim-side scripting 

Using either python or powershell (or maybe both if it can be abstract enough). This could allow things like running Responder.py or Empire on a compromised host.

**Mentor**: [@OJ](https://github.com/oj)

### Use SChannel in native Windows Meterpreter instead of embedded OpenSSL

[SChannel](https://msdn.microsoft.com/en-us/library/windows/desktop/ms678421(v=vs.85).aspx) is Windows' built-in TLS library.

**Mentor**: [@OJ](https://github.com/oj)

