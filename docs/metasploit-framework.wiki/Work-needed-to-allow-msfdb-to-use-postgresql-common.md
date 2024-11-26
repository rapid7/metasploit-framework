# Work needed to allow msfdb to use postgresql-common

Linux distributions, such as Debian and Kali Linux, use [postgresql-common (Multi-Version/Multi-Cluster PostgreSQL architecture)](https://salsa.debian.org/postgresql/postgresql-common) wrappers to interact with one or more PostgreSQL installations. Therefore, commands such as `initdb` and `pg_ctl` are not in the user's `PATH`. `msfdb` currently assumes these programs are available in the `PATH`. In order to support platforms that use the `postgresql-common` wrappers, `msfdb` would need to determine if it is running on such a platform and modify the commands used to perform the various setup and configuration operations. See the section "msfdb support for postgresql-common" for additional details.

## `msfdb` support for postgresql-common

### Requirements

* Determine if the system is using `postgresql-common`.
* Ideally, allow a user without elevated privileges to setup a database for use with Metasploit.
* Determine the current version of PostgreSQL on the system when multiple versions might be installed in parallel.
* The port number used for the server when `pg_createcluster` is run without a port number option defaults to the "next free port starting from 5432". If we don't specify the port number when calling `pg_createcluster` we can scrape the port number from the `pg_lsclusters` output.

```
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_lsclusters --no-header | awk '/^9.6/ { if ($2 == "msf") { print $3; } }'
5433
```

### Notes

Debian's [postgresql-common (Multi-Version/Multi-Cluster PostgreSQL architecture)](https://salsa.debian.org/postgresql/postgresql-common) contains PostgreSQL wrapper tools:

* `pg_lsclusters`: list all available clusters with their status and configuration
* `pg_createcluster`: wrapper for `initdb`, sets up the necessary configuration structure
    * `pg_createcluster [options] version name [-- initdb options]`
* `pg_ctlcluster`: wrapper for `pg_ctl`, control the cluster postgres server
    * pg_ctlcluster [options] cluster-version cluster-name action -- [pg_ctl options]
    * where action is one of start, stop, restart, reload, promote
* `pg_dropcluster`: remove a cluster and its configuration
    * pg_dropcluster [--stop] cluster-version cluster-name
* `pg_wrapper`: wrapper for PostgreSQL client commands
    * client-program [--cluster version/cluster] [...]
    * ( client-program: psql, createdb, dropuser, and all other client programs installed in /usr/lib/postgresql/ version/bin).

The "database cluster" simply refers to a set of databases on a single server rather than a group of multiple database servers.

### Manually create and initialize MSF database using postgresql-common

#### Issues

Encountered permissions issues when attempting to create a cluster.

```
pg_createcluster --user=$(whoami) --encoding=UTF8 9.6 msf -- --username=$(whoami) --auth-host=trust --auth-local=trust
install: cannot change permissions of '/etc/postgresql/9.6/msf': No such file or directory
Error: could not create configuration directory; you might need to run this program with root privileges
```

Requiring root privileges may be prohibitive to user installs of MSF. How can we create a cluster without root privileges? Adding the user to the postgres group and attempting to `sudo -u postgres` the command, however, resulted in the same error message. Looking closer at the various commands and discovered the following in the man page for `pg_wrapper`.

```
PG_CLUSTER_CONF_ROOT
    This specifies an alternative base directory for cluster configurations. This is usually
    /etc/postgresql/, but for testing/development purposes you can change this to point to e. g. your
    home directory, so that you can use the postgresql-common tools without root privileges.
```

#### Working Solution

Create cluster ("initdb") to set up the necessary configuration structure:

Note, running `mkdir -p $HOME/.local/etc/postgresql;` before the `pg_createcluster` command didn't stop the "install: cannot change owner and permissions of '/home/msfdev/.local/etc/postgresql/9.6': Operation not permitted" message from appearing. This appears to be a warning only and doesn't seem to affect cluster creation.

```
mkdir -p $HOME/.local/var/log/postgresql; PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_createcluster --user=$(whoami) --datadir=$HOME/msf-db-datadir --socketdir=$HOME/.local/var/run/postgresql --logfile=$HOME/.local/var/log/postgresql/postgresql-version-msf.log --encoding=UTF8 9.6 msf -- --username=$(whoami) --auth-host=trust --auth-local=trust
install: cannot change owner and permissions of '/home/msfdev/.local/etc/postgresql/9.6': Operation not permitted
Creating new cluster 9.6/msf ...
config /home/msfdev/.local/etc/postgresql/9.6/msf
data /home/msfdev/msf-db-datadir
locale en_US.UTF-8
socket /home/msfdev/.local/var/run/postgresql
port 5433
```

Check cluster was successfully created and appears in the list of all available clusters:

```
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_lsclusters
Ver Cluster Port Status Owner Data directory Log file
9.6 msf 5433 down msfdev /home/msfdev/msf-db-datadir /home/msfdev/.local/var/log/postgresql/postgresql-version-msf.log
```

Start postmaster server for the cluster ("pg_ctl"):

```
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_ctlcluster 9.6 msf start
```

Check that the cluster was successfully started:

```
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_lsclusters
Ver Cluster Port Status Owner Data directory Log file
9.6 msf 5433 online msfdev /home/msfdev/msf-db-datadir /home/msfdev/.local/var/log/postgresql/postgresql-version-msf.log
```

Perform `msfdb`'s `write_db_config` method work by manually creating the `~/.msf4/database.yml` file:

```
development: &pgsql
  adapter: postgresql
  database: msf
  username: msf
  password: Password123
  host: 127.0.0.1
  port: 5433
  pool: 200

production: &production
  <<: *pgsql

test:
  <<: *pgsql
  database: msftest
  username: msftest
  password: Password123
```

Create database users:

Note, these steps are from `msfdb`'s `init_db` method. The following example only creates the main MSF user account and not the test account.

```
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql psql --cluster 9.6/msf -c "create user msf with password 'Password123';" postgres
CREATE ROLE
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql psql --cluster 9.6/msf -c "alter role msf createdb;" postgres
ALTER ROLE
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql psql --cluster 9.6/msf -c "alter role msf with password 'Password123';" postgres
ALTER ROLE
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql createdb --cluster 9.6/msf -O msf -h 127.0.0.1 -U msf -E UTF-8 -T template0 msf
```

Perform `msfdb`'s `write_db_client_auth_config` method work, except it needs to write the `pg_hba.conf` file now stored in under `PG_CLUSTER_CONF_ROOT` and inside the `version/cluster-name` directory. In this example that location is: `$HOME/.local/etc/postgresql/9.6/msf/pg_hba.conf`.

Perform `msfdb`'s `restart_db` method work, by stopping and then starting the server. Stop and then start postmaster server for the cluster ("pg_ctl"):

```
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_ctlcluster 9.6 msf stop
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_ctlcluster 9.6 msf start
```

Check that the cluster was successfully started:

```
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_lsclusters
Ver Cluster Port Status Owner Data directory Log file
9.6 msf 5433 online msfdev /home/msfdev/msf-db-datadir /home/msfdev/.local/var/log/postgresql/postgresql-version-msf.log
```

Create initial database schema:

Note, these steps are from `msfdb`'s `init_db` method.

```
cd ~/metasploit-framework
bundle exec rake db:migrate
```

Start `msfconsole` and verify postgresql connection using the `db_status` command:

```
# disable or remove ~/.msf4/config if it is configured to auto connect to a data service
mv ~/.msf4/config ~/.msf4/config.disable
./msfconsole
...
msf5 > db_status 
[*] Connected to msf. Connection type: postgresql.
```

Drop (delete) the cluster:

```
PG_CLUSTER_CONF_ROOT=$HOME/.local/etc/postgresql pg_dropcluster 9.6 msf
```