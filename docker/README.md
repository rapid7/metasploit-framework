# Metasploit in Docker
## Getting Started

To run `msfconsole`
```bash
docker-compose run --rm --service-ports ms
```

To run `msfvenom`
```bash
docker-compose run --rm ms ./msfvenom
```

### I don't like typing `docker-compose --rm ...`

We have included some binstubs `./bin`, you can symlink them to your path.

Assuming you have `$HOME/bin`, and it's in your `$PATH`. You can run this from the project root:

```bash
ln -s `pwd`/docker/bin/msfconsole $HOME/bin/
ln -s `pwd`/docker/bin/msfvenom $HOME/bin/
```

If you set the environment variable `MSF_BUILD` the container will be rebuilt.

```bash
MSF_BUILD=1 ./docker/bin/msfconsole
MSF_BUILD=1 ./docker/bin/msfconsole-dev
```

### But I want reverse shells...

By default we expose port `4444`. You'll need to set `LHOST` to be a hostname/ip
of your host machine.

If you want to expose more ports, or have `LHOST` prepopulated with a specific
value; you'll need to setup a local docker-compose override for this.

Create `docker/docker-compose.local.override.yml` with:
```yml
version: '2'
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
echo "COMPOSE_FILE=./docker-compose.yml:./docker/docker-compose.local.override.yml" >> .env
```
Now you should be able get reverse shells working

## Developing

To setup you environment for development, you need to add `docker/docker-compose.development.override.yml`
to your `COMPOSE_FILE` environment variable.

If you don't have a `COMPOSE_FILE` environment variable, you can set it up with this:

```bash
echo "COMPOSE_FILE=./docker-compose.yml:./docker/docker-compose.development.override.yml" >> .env
```

Alternatively you can also use the `msfconsole-dev` binstub.
