# Install oracle InstantClient


InstantClient 10 is recommended to allow you to talk with 8,9,10,&11 server versions.

Go to <https://www.oracle.com/database/technologies/instant-client/downloads.html> and select the link corresponding to your UNIX PC's architecture. Example for Linux x64, use the Instant Client for Linux x86-64 link, which should take you to <https://www.oracle.com/database/technologies/instant-client/linux-x86-64-downloads.html>

Grab these:
* Instant Client Package - Basic
* Instant Client Package - SDK (devel)
* Instant Client Package - SQL*Plus (not needed for Metasploit but useful to have)

unzip into /opt/oracle
```sh
cd /opt/oracle
unzip /opt/oracle/oracle-instantclient-basic-10.2.0.4-1.i386.zip
unzip /opt/oracle/oracle-instantclient-sqlplus-10.2.0.4-1.i386.zip
unzip /opt/oracle/oracle-instantclient-devel-10.2.0.4-1.i386.zip
```

Now set up a symlink so the gem installation can find the right lib:
```sh
ln -s libclntsh.so.10.1 libclntsh.so
```
# Set up your environment

You can either create .sh file to make the appropriate changes when you need it or just add it to your .bashrc

```sh
export PATH=$PATH:/opt/oracle/instantclient_10_2
export SQLPATH=/opt/oracle/instantclient_10_2
export TNS_ADMIN=/opt/oracle/instantclient_10_2
export LD_LIBRARY_PATH=/opt/oracle/instantclient_10_2
export ORACLE_HOME=/opt/oracle/instantclient_10_2
```

# Additional steps for Kali Linux

If you are using Kali Linux, you need to perform a couple of additional steps before the Oracle client gem will build properly. First, set your path to prefer the correct version of ruby so that Metasploit can use it:
```
root@kali:~/ruby-oci8-ruby-oci8-2.1.8# export PATH=/opt/metasploit/ruby/bin:$PATH
```

Next, install libgmp (needed to build the gem):
```
root@kali:~/ruby-oci8-ruby-oci8-2.1.8# apt-get install libgmp-dev
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

# Install the gem

Back in your Metasploit directory, copy `Gemfile.local.example` to `Gemfile.local`, then add the following line to the `:local` group
```ruby
  gem 'ruby-oci8'
```

Update gems:
```sh
bundle --gemfile Gemfile.local
```
