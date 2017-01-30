Project Ideas in no particular order.

# Convert between cmd/unix/* and the various interpreted language architectures

Perl, Python, and Ruby scripts can all be run via a short command line invocation. It would be nice to be able to use these payloads in `ARCH_CMD` contexts as well as their own separate architectures (`ARCH_PYTHON`, `ARCH_RUBY`).

# Use SChannel in native Windows Meterpreter instead of embedded OpenSSL [@OJ](https://github.com/oj)

[SChannel](https://msdn.microsoft.com/en-us/library/windows/desktop/ms678421(v=vs.85).aspx) is Windows' built-in TLS library.

# Automated exploit reliability scoring [@busterb](https://github.com/busterb)

Automatically run a module over and over, determine success rates.

# Exploit regression testing. 

# A categorical focus, like "make all X exploits badass", or add a full suite of modules around particular gear or vendor stack. [@hdm](https://github.com/hdm)

# Modifications to Meterpreter that allow for scripts to run asynchronously. [@OJ](https://github.com/oj)

# Make it possible for post modules to take a payload, move the `exploit/*/local` modules that aren't actually exploits back to `post/` [@egypt](https://github.com/egypt)

# SMB2 support [@egypt](https://github.com/egypt)

(see also https://github.com/rapid7/ruby_smb)