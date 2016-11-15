# Metasploit Framework Open Source Nightly Installers

Metaploit framework installers are built nightly for those wanting to track the bleeding edge, or those who would like a simplified Metasploit framework setup experience. These packages are built for OS X, Windows and various Linux distributions, including a complete bundled Ruby environment and PostgreSQL database. The installers integrate with your system packaging nicely and are easy to add and remove.

# Linux and OS X quick installation

The following script invocation will import the Rapid7 signing key and setup the package for all supported Linux and OS X systems:

```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

These packages integrate into your OS's native package management and can either be updated with the ```msfupdate``` command or using your preferred package manager. On Kali Linux systems, if your database has already been setup with ```msfdb init```, these packages will continue to use that database.

# OS X graphical installation

The latest OS X installer package can also be downloaded directly here: https://osx.metasploit.com/metasploitframework-latest.pkg, with the last 10 builds archived at https://osx.metasploit.com/. Simply download and launch the installer to install Metaploit Framework with all of its dependencies.  Once installed, initially launch msfconsole as ```/opt/metasploit-framework/bin/msfconsole```. A series of prompts will help you setup a database and add Metasploit to your local PATH. You can also follow the Linux instructions below to install in a single step.

# Linux package details

Linux packages are built nightly for .deb (64-bit and 32-bit x86) and .rpm (64-bit x86) systems. Debian/Ubuntu packages are available at https://apt.metasploit.com and CentOS/Redhat/Fedora packages are located at https://rpm.metasploit.com.

# Windows

The latest Windows installer is located here: https://windows.metasploit.com/metasploitframework-latest.msi, with the last 10 builds archived at https://windows.metasploit.com/. To install, simply download the .msi package, adjust your Antivirus as-needed to ignore c:\metasploit-framework, double-click and enjoy. The msfconsole command and all related tools will be added to the system %PATH% environment variable.

# Detailed installation guide

You can access a detailed installation guide here: https://community.rapid7.com/docs/DOC-3163

# Improving these installers

The source code to these installers is located here: https://github.com/rapid7/metasploit-omnibus
Installer improvements are welcome and encouraged.
