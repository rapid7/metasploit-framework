## Setup

This contains setup steps used for acceptance testing of the `cmd_exec` API. We will make use of the gcc docker image to 
build out the C binaries to then be uploaded to the host machine, so they can be used as part of the `cmd_exec` 
create process API.

This directory contains:
- C executable `show_args.c`
This file is used as part of the `cmd_exec` testing as it requires a file to take args, then loop over them and output 
those args back to the user.

- Makefile to build the binaries `makefile.mk`
This file is used to create the binaries for both Windows and Linux that the docker command below will make use of.

- Precompiled binaries for Windows
  - `show_args.exe`

- Precompiled binaries for Linux and Mettle
  - `show_args`

- Precompiled binaries for macOS
  - `show_args_macos`

## Compile binaries locally

We make use of gcc for this: https://hub.docker.com/_/gcc

- Run:
```shell
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp gcc:11.4.0 /bin/bash -c "apt update && apt install -y gcc-mingw-w64 && make all -f makefile.mk"
```

You will need to compile the OSX payload separately on an OSX machine, Docker is not supported.
