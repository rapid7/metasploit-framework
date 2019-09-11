Installers are built nightly for OS X, Windows (64-bit) and Linux.  These installers include dependencies (like Ruby and PostgreSQL) and integrate with your package manager, so they're easy to update.

## What operating system are you using?

<details><summary><B>Linux / Mac OS X</B></summary>

## Installing Metasploit on Linux / Mac OS X

The following script invocation will import the Rapid7 signing key and setup the package for supported Linux and OS X systems:

```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

These packages integrate into your package manager and can be updated with ```msfupdate``` or with your package manager. On first start, these packages will automatically setup the database or use your existing database.

<details><summary>Expand manual installation instructions</summary>

### Linux manual installation

Linux packages are built nightly for .deb (i386, amd64, armhf, arm64) and .rpm (64-bit x86) systems. Debian/Ubuntu packages are available at https://apt.metasploit.com and CentOS/Redhat/Fedora packages are located at https://rpm.metasploit.com.

### OS X manual installation

The latest OS X installer package can also be downloaded directly here: https://osx.metasploit.com/metasploitframework-latest.pkg, with the last 10 builds archived at https://osx.metasploit.com/. Simply download and launch the installer to install Metaploit Framework with all of its dependencies.  Once installed, initially launch msfconsole as ```/opt/metasploit-framework/bin/msfconsole``` from a terminal console. A series of prompts will help you setup a database and add Metasploit to your local PATH. You can also follow the quick-installation instructions above to install in a single step.

</details>
</details>

<p>
<details><summary><b>Windows</b></summary>

## Installing Metasploit on Windows

Download the [latest Windows installer](https://windows.metasploit.com/metasploitframework-latest.msi) or [view older builds](https://windows.metasploit.com/). To install, simply download the .msi package, adjust your Antivirus as-needed to ignore c:\metasploit-framework, double-click and enjoy. The msfconsole command and all related tools will be added to the system %PATH% environment variable.

### Windows Anti-virus software flags the contents of these packages!

If you downloaded Metasploit from us, there is no cause for alarm.  We pride ourselves on offering the ability for our customers and followers to have the same toolset that the hackers have so that they can test systems more accurately.  Because these (and the other exploits and tools in Metasploit) are identical or very similar to existing malicious toolsets, they can be used for nefarious purposes, and they are often flagged and automatically removed by antivirus programs, just like the malware they mimic.

</details>

## Improving these installers

Feel free to review and help improve [the source code for our installers](https://github.com/rapid7/metasploit-omnibus).