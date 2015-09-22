# Metasploit Framework Nightly Installers

Metaploit framework installers are built nightly for those wanting to track the bleeding edge, or those who would like a simplified Metasploit framework setup experience. These packages are built for OS X, Windows and various Linux distributions, including a complete bundled Ruby environment and PostgreSQL database. The installers integrate with your system packaging nicely and are easy to add and remove.

# Windows

The latest Windows installer is located here: http://windows.metasploit.com/metasploitframework-latest.msi, with the last 10 builds archived at http://windows.metasploit.com/. To install, simply download the .msi package, adjust AV appropriately to ignore c:\metasploit-framework, double-click and enjoy. msfconsole and related tools will be added to the system PATH. Use the ```msfdb``` command to manage initializing, starting or stopping the database. ```msfupdate``` will download and install the latest MSI, and ```msfremove``` will uninstall the package (or you can remove it as a normal MSI package).

# OS X

The latest OS X installer is located here: http://osx.metasploit.com/metasploitframework-latest.pkg, with the last 10 builds archived at http://osx.metasploit.com/. It works similarly to the Windows installer with double-click installation of Metasploit Framework with all of its dependencies.  Once installed, initially launch msfconsole as ```/opt/metasploit-framework/bin/msfconsole```. A series of prompts will helpy you setup a database and add Metasploit to your local PATH. You can also follow the Linux instructions below to install in a single step.

# Linux

Linux packages are built nightly for .deb (64-bit and 32-bit x86) and .rpm (64-bit x86) systems. Debian/Ubuntu packages are available at http://apt.metasploit.com and CentOS/Redhat/Fedora packages are located at http://rpm.metasploit.com. The following script invocation will Rapid7 signing key and setup the package for all supported Linux and OSX systems:

```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

These packages integrate into your OS's native package management and can either be updated with the ```msfupdate``` command or using your preferred package manager. On Kali Linux systems, if your database has already been setup with ```msfdb init```, these packages will continue to use that database.

The source code to these installers is located here: https://github.com/rapid7/metasploit-omnibus
Installer improvements are welcome and encouraged.