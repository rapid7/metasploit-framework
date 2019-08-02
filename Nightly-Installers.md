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

<details><summary>Expand a full log of the installation process on an Ubuntu-based Chromebook</summary>

```
bcook@localhost:~$ uname -a
Linux localhost 3.14.0 #1 SMP PREEMPT Mon Feb 6 21:59:30 PST 2017 armv7l armv7l armv7l GNU/Linux
bcook@localhost:~$ curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
>   chmod 755 msfinstall && \
>   ./msfinstall
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5394  100  5394    0     0   5609      0 --:--:-- --:--:-- --:--:--  5607
Switching to root user to update the package
[sudo] password for bcook: 
Adding metasploit-framework to your repository list..OK
Updating package cache..OK
Checking for and installing update..
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following NEW packages will be installed:
  metasploit-framework
0 upgraded, 1 newly installed, 0 to remove and 2 not upgraded.
Need to get 148 MB of archives.
After this operation, 358 MB of additional disk space will be used.
Get:1 http://downloads.metasploit.com/data/releases/metasploit-framework/apt lucid/main armhf metasploit-framework armhf 4.13.23+20170217143300.git.1.85dca6a~1rapid7-1 [148 MB]
Fetched 148 MB in 19s (7743 kB/s)                                                                                                    
Selecting previously unselected package metasploit-framework.
(Reading database ... 28449 files and directories currently installed.)
Preparing to unpack .../metasploit-framework_4.13.23+20170217143300.git.1.85dca6a~1rapid7-1_armhf.deb ...
Unpacking metasploit-framework (4.13.23+20170217143300.git.1.85dca6a~1rapid7-1) ...


Setting up metasploit-framework (4.13.23+20170217143300.git.1.85dca6a~1rapid7-1) ...
update-alternatives: using /opt/metasploit-framework/bin/msfbinscan to provide /usr/bin/msfbinscan (msfbinscan) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfconsole to provide /usr/bin/msfconsole (msfconsole) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfd to provide /usr/bin/msfd (msfd) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfdb to provide /usr/bin/msfdb (msfdb) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfelfscan to provide /usr/bin/msfelfscan (msfelfscan) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfmachscan to provide /usr/bin/msfmachscan (msfmachscan) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfpescan to provide /usr/bin/msfpescan (msfpescan) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfrop to provide /usr/bin/msfrop (msfrop) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfrpc to provide /usr/bin/msfrpc (msfrpc) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfrpcd to provide /usr/bin/msfrpcd (msfrpcd) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfupdate to provide /usr/bin/msfupdate (msfupdate) in auto mode
update-alternatives: using /opt/metasploit-framework/bin/msfvenom to provide /usr/bin/msfvenom (msfvenom) in auto mode
Run msfconsole to get started
W: --force-yes is deprecated, use one of the options starting with --allow instead.
bcook@localhost:~$ msfconsole 

 ** Welcome to Metasploit Framework Initial Setup **
    Please answer a few questions to get started.


Would you like to use and setup a new database (recommended)? y
Creating database at /home/bcook/.msf4/db
Starting database at /home/bcook/.msf4/db...success
Creating database users
Creating initial database schema

 ** Metasploit Framework Initial Setup Complete **

       =[ metasploit v4.13.23-dev-584850f1f8a1a74b69b5cea16c700c9fd1b8e4c6]
+ -- --=[ 1622 exploits - 924 auxiliary - 282 post        ]
+ -- --=[ 472 payloads - 39 encoders - 9 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

msf >
```

</details>

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