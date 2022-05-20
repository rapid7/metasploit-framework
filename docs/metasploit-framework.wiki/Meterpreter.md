Meterpreter is an advanced payload that has been part of Metasploit since 2004. Originally written in C by Matt "skape" Miller, dozens of contributors have provided additional code, including implementations in PHP, Python, and Java. The payload continues to be frequently updated as part of Metasploit development.

Meterpreter development occurs in [the metasploit-payloads repository](https://github.com/rapid7/metasploit-payloads) and the compiled results are published as part of the [metasploit-payloads gem](https://rubygems.org/gems/metasploit-payloads). For a detailed understanding of the Meterpreter architecture, please review the [original specification](http://www.hick.org/code/skape/papers/meterpreter.pdf).

Additional documentation about Meterpreter can be found on this wiki:
 * [[Meterpreter Reliable Network Communication]]
 * [[Meterpreter Transport Control]]
 * [[Meterpreter HTTP Communication]]
 * [[Meterpreter Timeout Control]]
 * [[Meterpreter Sleep Control]]
 * [[Meterpreter Stageless Mode]]
 * [[Meterpreter Unicode Support]]
 * [[Meterpreter Configuration]]
 * [[Payload UUID]]

Extension-specific documentation:
 * [[Python Extension]]
 * [[Powershell Extension]]

A wishlist of features is maintained at the [[Meterpreter Wishlist]] page.

Examples of specific use cases can also be found on this wiki:
 * [[Meterpreter Paranoid Mode]]

Those interested in the technical details of Meterpeter, along with rationale behind some of the implementations, should read the following:
 * [[The ins and outs of HTTP and HTTPS communications in Meterpreter and Metasploit Stagers]]

Got dead Meterpreter sessions? Read this: [[Debugging Dead Meterpreter Sessions]].

# Architecture

To avoid confusion, the victim running meterpreter is always called the server and the ruby side controlling it is always called the client, regardless of the direction of the network transport connection.

The Meterpreter server is broken into several pieces:
  - `metsrv.dll` and `meterpreter.{jar,php,py}` - this is the heart of meterpreter where the protocol and extension systems are implemented.
  - `ext_server_stdapi.{dll,jar,php,py}` - this extension implements most of the commands familiar to users.
  - `ext_server_*.{dll,jar,php,py}` - other extensions provide further functionality and can be specific to particular environments.

## Delivering Meterpreter

1. Using a technique developed by Stephen Fewer called Reflective DLL Injection (RDI), metsrv.dll's header is modified to be usable as shellcode. From there, Metasploit can embed it in an executable or run it via an exploit like any other shellcode.





