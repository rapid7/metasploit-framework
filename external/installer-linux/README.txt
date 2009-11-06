****************************************
* Metasploit Framework Linux Installer *
****************************************

The Metasploit installer for Linux provides a self-contained execution
environment for the Metasploit Framework. This includes the Ruby interpreter,
the RubyGems package, SQLite3, and Subversion. The package also includes
binary copies of the libraries needed to support these tools.

The installer is built using binaries from Ubuntu 6.06 Server. This old
version is necessary for the compiled tools to be compatible with older versions
of the GLIBC library.

The following applications/libraries are built from source:
	- Ruby 1.9.1
	- RubyGems
	- SQLite3-Ruby
	- Subversion
	- Lorcon2

The following libraries are taken from Ubuntu:
	- libssl.so.0.9.8
	- libutil-2.3.6.so
	- libcrypto.so.0.9.8
	- libncursesw.so.5.5
	- libsqlite3.so.0.8.6
	- libncurses.so.5.5
	- libz.so.1.2.3
	- libaprutil-1.so.0.3.9
	- libserf-0.so.0.0.0
	- libapr-1.so.0.3.8
	- libdb-4.3.so
	- libpcap.so.0.9.4
	- libexpat.so.1.0.0

While the source code for each of these applications and libraries are easily
available from the upstream repository, we will make them available directly
from the Metasploit server on demand.

The installer itself is created with makeself

