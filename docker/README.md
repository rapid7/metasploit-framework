# Metasploit in Docker
## Getting Started

To run `msfconsole`
```bash
./docker/bin/msfconsole
```

or

```bash
docker-compose build
docker-compose run --rm --service-ports -e MSF_UID=$(id -u) -e MSF_GID=$(id -g) ms
```
To run `msfvenom`
```bash
./docker/bin/msfvenom
```

or

```bash
docker-compose build
docker-compose run --rm --no-deps -e MSF_UID=$(id -u) -e MSF_GID=$(id -g) ms ./msfvenom
```

You can pass any command line arguments to the binstubs or the docker-compose command and they will be passed to `msfconsole` or `msfvenom`. If you need to rebuild an image (for example when the Gemfile changes) you need to build the docker image using `docker-compose build` or supply the `--rebuild` parameter to the binstubs.

### But I want reverse shells...

By default we expose port `4444`.

If you want to expose more ports, or have `LHOST` prepopulated with a specific
value; you'll need to setup a local docker-compose override for this.

Create `docker-compose.local.override.yml` with:
```yml
version: '3'
services:
  ms:
    environment:
      # example of setting LHOST
      LHOST: 10.0.8.2
    # example of adding more ports
    ports:
      - 8080:8080
```

Make sure you set `LHOST` to valid hostname that resolves to your host machine.

Now you need to set the `COMPOSE_FILE` environment variable to load your local
override.

```bash
echo "COMPOSE_FILE=./docker-compose.yml:./docker-compose.override.yml:./docker-compose.local.override.yml" >> .env
```
Now you should be able get reverse shells working
