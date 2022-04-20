There are currently two main ways to debug Meterpreter sessions:

1. Log all networking requests between msfconsole and Meterpreter, i.e. TLV Packets
2. Generate a custom Meterpreter debug build extra logging present

### Log Meterpreter TLV Packets

This can be enabled for any Meterpreter session, and does not impact the Metasploit build:

```
msf6 > setg SessionTlvLogging true
SessionTlvLogging => true
```

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

Allowed values:

- `setg SessionTlvLogging true` - Enable network logging, defaulting to console
- `setg SessionTlvLogging false` - Disable all logging
- `setg SessionTlvLogging console` - Log to the current msfconsole instance
- `setg SessionTlvLogging file:/tmp/session.txt` - Write the network traffic logs to an arbitrary file

### Meterpreter debug builds

- `MeterpreterDebugBuild` - When set to true ...etc etc...
- `MeterpreterDebugLogging` - When MeterpreterDebugBuild is set. The file path where logfiles will be written to on the remote machine. Only used if MeterpreterDebugBuild is set to true. Example allowed values are: rpath:/{file},  rpath:./{file} and rpath:{drive_letter}:{file}