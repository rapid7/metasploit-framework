## Vulnerable Application

### Docker-Compose Build

Using docker-compose we can build a fairly robust system with plenty of information to pilfer.

Based off of [Ron Bowes Blog Post](https://www.labs.greynoise.io//grimoire/2023-11-29-owncloud-redux/)

A list of environment variables is posted [here](https://github.com/owncloud-docker/base/blob/master/ENVIRONMENT.md#environment-variables)

```
version: "3"

services:
  owncloud:
    image: owncloud/server:10.12.1
    container_name: owncloud_server
    restart: always
    ports:
      - 8080:8080
    depends_on:
      - mariadb
      - redis
    environment:
      - OWNCLOUD_DOMAIN=localhost:8080
      - OWNCLOUD_TRUSTED_DOMAINS=localhost
      - OWNCLOUD_DB_TYPE=mysql
      - OWNCLOUD_DB_NAME=owncloud
      - OWNCLOUD_DB_USERNAME=owncloud
      - OWNCLOUD_DB_PASSWORD=owncloud
      - OWNCLOUD_DB_HOST=mariadb
      - OWNCLOUD_ADMIN_USERNAME=admin_username
      - OWNCLOUD_ADMIN_PASSWORD=admin_password
      - OWNCLOUD_MYSQL_UTF8MB4=true
      - OWNCLOUD_REDIS_ENABLED=true
      - OWNCLOUD_REDIS_HOST=redis
      - APACHE_LOG_LEVEL=trace6
      - OWNCLOUD_MAIL_SMTP_PASSWORD=smtp_password
      - OWNCLOUD_MAIL_SMTP_NAME=smtp_username
      - OWNCLOUD_LICENSE_KEY=1122333
      - OWNCLOUD_OBJECTSTORE_KEY=owncloud123456
      - OWNCLOUD_OBJECTSTORE_SECRET=secret123456
      - OWNCLOUD_OBJECTSTORE_REGION=us-east-1
    healthcheck:
      test: ["CMD", "/usr/bin/healthcheck"]
      interval: 30s
      timeout: 10s
      retries: 5

  mariadb:
    image: mariadb:10.11 # minimum required ownCloud version is 10.9
    container_name: owncloud_mariadb
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=owncloud
      - MYSQL_USER=owncloud
      - MYSQL_PASSWORD=owncloud
      - MYSQL_DATABASE=owncloud
      - MARIADB_AUTO_UPGRADE=1
    command: ["--max-allowed-packet=128M", "--innodb-log-file-size=64M"]
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-u", "root", "--password=owncloud"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:6
    container_name: owncloud_redis
    restart: always
    command: ["--databases", "1"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
```

You may need to add an aditional entry to `OWNCLOUD_TRUSTED_DOMAINS` which has the IP address of the host, such as `OWNCLOUD_TRUSTED_DOMAINS=localhost,192.68.1.1`

## Verification Steps
Example steps in this format (is also in the PR):

1. Install the application
1. Start msfconsole
1. Do: `use [module path]`
1. Do: `run`
1. You should get a shell.

## Options
List each option and how to use it.

### Option Name

Talk about what it does, and how to use it appropriately. If the default value is likely to change, include the default value here.

## Scenarios
Specific demo of using the module that might be useful in a real world scenario.

### Version and OS

```
code or console output
```

For example:

To do this specific thing, here's how you do it:

```
msf > use module_name
msf auxiliary(module_name) > set POWERLEVEL >9000
msf auxiliary(module_name) > exploit
```
