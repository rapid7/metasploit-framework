# Install oracle InstantClient


InstantClient 10 is recommneded to allow you to talk with 8,9,10,&11 server versions.

Go to http://www.oracle.com/technology/software/tech/oci/instantclient/index.html

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

# Install the gem

Back in your Metasploit directory, copy `Gemfile.local.example` to `Gemfile.local`, then add the following line to the `:local` group
```ruby
  gem 'ruby-oci8'
```

Update gems:
```sh
bundle --gemfile Gemfile.local
```