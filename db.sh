#!/bin/bash

# Set Postgresql to start on boot and set reasonable defaults
echo '1234' | sudo -kS update-rc.d postgresql enable &&
echo '1234' | sudo  -S service postgresql start &&
cat <<EOF> $HOME/pg-utf8.sql
update pg_database set datallowconn = TRUE where datname = 'template0';
\c template0
update pg_database set datistemplate = FALSE where datname = 'template1';
drop database template1;
create database template1 with template = template0 encoding = 'UTF8';
update pg_database set datistemplate = TRUE where datname = 'template1';
\c template1
update pg_database set datallowconn = FALSE where datname = 'template0';
\q
EOF
sudo -u postgres psql -f $HOME/pg-utf8.sql &&
sudo -u postgres createuser rahul -dRS &&
sudo -u postgres psql -c \
  "ALTER USER rahul with ENCRYPTED PASSWORD '1234';" &&
sudo -u postgres createdb --owner rahul msf_dev_db2 &&
sudo -u postgres createdb --owner rahul msf_test_db2 &&
cat <<EOF> $HOME/.msf4/database.yml
# Development Database
development: &pgsql
  adapter: postgresql
  database: msf_dev_db2
  username: rahul
  password: 1234
  host: localhost
  port: 5432
  pool: 5
  timeout: 5

# Production database -- same as dev
production: &production
  <<: *pgsql

# Test database -- not the same, since it gets dropped all the time
test:
  <<: *pgsql
  database: msf_test_db2
EOF
