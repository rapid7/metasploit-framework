## Setup

This contains a custom container image used for Python-based acceptance testing. It provides multiple
CPython interpreter versions (installed via [pyenv](https://github.com/pyenv/pyenv), including a couple of
very old releases that need a custom-built OpenSSL to compile) so that payloads exercising Python's SSL
support can be tested against the interpreter/OpenSSL combinations they actually target.

This image is published to [`rapid7/msf-pyenv`](https://hub.docker.com/r/rapid7/msf-pyenv) on Docker Hub
by the `framework_pyenv_image_publish` Jenkins pipeline, which any maintainer can trigger manually to
rebuild/republish it.

## Running

- Build:
```shell
docker build -f Containerfile -t pyenv:local .
```

- Run a specific interpreter version by setting `PYENV_VERSION`:
```shell
docker run --rm -e PYENV_VERSION=3.13.13 pyenv:local python --version
```

There's no `docker-compose.yml` for this fixture — unlike the long-running service fixtures (SMB, SSH,
LDAP), the acceptance tests invoke this image per-payload-execution via `docker run`/`podman run`, so
there's nothing to start/stop as a standing service.
