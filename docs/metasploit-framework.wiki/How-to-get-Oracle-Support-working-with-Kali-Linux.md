This is an update of the original blog post about how to get Oracle support working with Metasploit and Kali Linux, found [here](https://leonjza.github.io/blog/2014/08/17/kali-linux-oracle-support/).

Due to licensing issues, we cannot ship Oracle's proprietary client access libraries by default. As a result, you may see this error when running a Metasploit module:

```msf
msf auxiliary(oracle_login) > run

[-] Failed to load the OCI library: cannot load such file -- oci8
[-] See http://www.metasploit.com/redmine/projects/framework/wiki/OracleUsage for installation instructions
[*] Auxiliary module execution completed
msf auxiliary(oracle_login) > run
```
or
```msf
msf5 auxiliary(scanner/oracle/oracle_hashdump) > run

[-] Failed to load the OCI library: cannot load such file -- oci8
[-] Try 'gem install ruby-oci8'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

The general steps to getting Oracle support working are to install the Oracle Instant Client and development libraries, install the required dependencies for Kali Linux, then install the gem.

## Install the Oracle Instant Client
As root, create the directory `/opt/oracle`. Then download the [Oracle Instant Client](https://www.oracle.com/database/technologies/instant-client/downloads.html) packages for your version of Kali Linux. The packages you will need are:

* [instantclient-basic-linux.x64-23.6.0.24.10.zip](https://download.oracle.com/otn_software/linux/instantclient/2360000/instantclient-basic-linux.x64-23.6.0.24.10.zip)
* [instantclient-sqlplus-linux.x64-23.6.0.24.10.zip](https://download.oracle.com/otn_software/linux/instantclient/2360000/instantclient-sqlplus-linux.x64-23.6.0.24.10.zip)
* [instantclient-sdk-linux.x64-23.6.0.24.10.zip](https://download.oracle.com/otn_software/linux/instantclient/2360000/instantclient-sdk-linux.x64-23.6.0.24.10.zip)

Unzip these under `/opt/oracle`, and you should now have a path called `/opt/oracle/instantclient_23_6/`.

You also need to configure the appropriate environment variables, perhaps by inserting them into your .bashrc file, logging out and back in for them to apply.

```
export PATH=$PATH:/opt/oracle/instantclient_23_6
export SQLPATH=/opt/oracle/instantclient_23_6
export TNS_ADMIN=/opt/oracle/instantclient_23_6
export LD_LIBRARY_PATH=/opt/oracle/instantclient_23_6
export ORACLE_HOME=/opt/oracle/instantclient_23_6
```

If you have succeeded, you should be able to run `sqlplus` from a command prompt:
```
root@kali:/opt/oracle/instantclient_23_6# sqlplus

SQL*Plus: Release 12.2.0.1.0 Production on Tue Mar 26 20:40:24 2019

Copyright (c) 1982, 2016, Oracle.  All rights reserved.

Enter user-name:
```

## Install the ruby gem

First, download and extract the gem source release:

```
root@kali:~# wget https://github.com/kubo/ruby-oci8/archive/refs/tags/ruby-oci8-2.2.14.zip
--2019-03-26 20:31:11--  https://github.com/kubo/ruby-oci8/archive/refs/tags/ruby-oci8-2.2.14.zip
Resolving github.com (github.com)... 192.30.253.113, 192.30.253.112
Connecting to github.com (github.com)|192.30.253.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://codeload.github.com/kubo/ruby-oci8/zip/ruby-oci8-2.2.14 [following]
--2019-03-26 20:31:11--  https://codeload.github.com/kubo/ruby-oci8/zip/ruby-oci8-2.2.14
Resolving codeload.github.com (codeload.github.com)... 192.30.253.120, 192.30.253.121
Connecting to codeload.github.com (codeload.github.com)|192.30.253.120|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [application/zip]
Saving to: 'ruby-oci8-2.2.14.zip'

ruby-oci8-2.2.14.zip                     [ <=>                                                                ] 376.97K  2.36MB/s    in 0.2s    

2019-03-26 20:31:11 (2.36 MB/s) - 'ruby-oci8-2.2.14.zip' saved [386016]

root@kali:~# unzip ruby-oci8-2.2.14.zip 
Archive:  ruby-oci8-2.2.14.zip
0c85bf6da2f541de3236267b1a1b18f0136a8f5a
   creating: ruby-oci8-ruby-oci8-2.2.14/
  inflating: ruby-oci8-ruby-oci8-2.2.14/.gitignore  
  inflating: ruby-oci8-ruby-oci8-2.2.14/.travis.yml 
[...]
  inflating: ruby-oci8-ruby-oci8-2.2.14/test/test_rowid.rb
root@kali:~# cd ruby-oci8-ruby-oci8-2.2.14/
```

Install libgmp (needed to build the gem) and set the path to prefer the correct version of ruby so that Metasploit can use it.

```
root@kali:~/ruby-oci8-ruby-oci8-2.2.14# export PATH=/opt/metasploit/ruby/bin:$PATH

root@kali:~/ruby-oci8-ruby-oci8-2.2.14# apt-get install libgmp-dev
Reading package lists... Done
Building dependency tree
Reading state information... Done
Suggested packages:
  libgmp10-doc libmpfr-dev
The following NEW packages will be installed:
  libgmp-dev
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 0 B/610 kB of archives.
After this operation, 1,740 kB of additional disk space will be used.
Selecting previously unselected package libgmp-dev:amd64.
(Reading database ... 322643 files and directories currently installed.)
Unpacking libgmp-dev:amd64 (from .../libgmp-dev_2%3a5.0.5+dfsg-2_amd64.deb) ...
Setting up libgmp-dev:amd64 (2:5.0.5+dfsg-2) ...
```

Build and install the gem

```
root@kali:~/ruby-oci8-ruby-oci8-2.2.14# make
ruby -w setup.rb config
setup.rb:280: warning: assigned but unused variable - vname
setup.rb:280: warning: assigned but unused variable - desc
setup.rb:280: warning: assigned but unused variable - default2
---> lib
---> lib/dbd
<--- lib/dbd
---> lib/oci8
<--- lib/oci8
<--- lib
---> ext
---> ext/oci8
/opt/metasploit/ruby/bin/ruby /root/ruby-oci8-ruby-oci8-2.2.14/ext/oci8/extconf.rb
checking for load library path...
  LD_LIBRARY_PATH...
    checking /opt/metasploit/ruby/lib... no
    checking /opt/oracle/instantclient_23_6... yes
  /opt/oracle/instantclient_23_6/libclntsh.so.12.1 looks like an instant client.
checking for cc... ok
checking for gcc... yes
checking for LP64... yes
checking for sys/types.h... yes
checking for ruby header... ok
checking for OCIInitialize() in oci.h... yes
[...]
linking shared-object oci8lib_250.so
make[1]: Leaving directory `/root/ruby-oci8-ruby-oci8-2.2.14/ext/oci8'
<--- ext/oci8
<--- ext

root@kali:~/ruby-oci8-ruby-oci8-2.2.14# make install
ruby -w setup.rb install
setup.rb:280: warning: assigned but unused variable - vname
setup.rb:280: warning: assigned but unused variable - desc
setup.rb:280: warning: assigned but unused variable - default2
---> lib
mkdir -p /opt/metasploit/ruby/lib/ruby/site_ruby/2.5.0/
install oci8.rb /opt/metasploit/ruby/lib/ruby/site_ruby/2.5.0/
[...]
<--- ext
root@kali:~/ruby-oci8-ruby-oci8-2.2.14#
```
