#### Raptor Description
Raptor's primary purpose will be to provide all the communication methods needed for Metasploit. This includes Socket level code as well as protocol implmenetations. Raptor should be as standalone as possible. Other Gems should dep Raptor not the other way around.

#### Exploit Helper
Tentative name for another new Gem. This Gem will focus on code that is designed to assist in the Exploitation process but is not key to communicating over services or implementing a specific protocol. Examples would be the ropbuilder, SEH libraries, egghunter, etc.

#### Binary Manipulation
Placeholder name for another Gem centered entirely around the Binary parsing and Manipulation. This includes all the different parsing libraries for the various executable formats.

#### Meterpreter Client
Tenative name for a Meterpreter client-side API. This code is currently rolled together with the rest of Rex. Meterpreter itself is already a seperate repo. The client should just be a gem. (This may be integrated into MsfCore instead of a seperate Gem. Investigate Further)

#### Metasploit Core
The core lbiraries of the Metasploit Framework. If the code has to do with running and maintaing the functions of the Framework rather than doing tasks inside a module, it probably belongs here.

#### /dev/null
[see here](http://en.wikipedia.org/wiki//dev/null)

These are things which are not needed anymore and should be killed with fire.

#### wtf?
 These are the last few odd-men out. Currently unsure of where these things should move as we clear out Rex and dance around it's burnt out corpse.


| Final Home | Directory/File | Description |
| ---------- | -------------- | ----------- |
| [Raptor](https://github.com/rapid7/raptor/wiki/Rex-code-layout#raptor-description) | [io](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/io/) | IO constructs such as streams and stream servers etc.|
| [Raptor](https://github.com/rapid7/raptor/wiki/Rex-code-layout#raptor-description) | [mime](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/mime/) | Library for handling mime messages. |
| [Raptor](https://github.com/rapid7/raptor/wiki/Rex-code-layout#raptor-description) | [proto](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/proto) | Various Protocol libraries for communicating with different services |
| [Raptor](https://github.com/rapid7/raptor/wiki/Rex-code-layout#raptor-description) | [services](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/services) | defines different tcp services. Currently only defines a local tcp relay |
| [Raptor](https://github.com/rapid7/raptor/wiki/Rex-code-layout#raptor-description) | [socket](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/socket/) | Holds all the socket, comm, and siwtchboard classes for handling network communications |
| [Raptor](https://github.com/rapid7/raptor/wiki/Rex-code-layout#raptor-description) | [sslscan](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/sslscan/) | Classes for SSLScan functionality. Allows discovery of SSL support on any tcp service |
| [Raptor](https://github.com/rapid7/raptor/wiki/Rex-code-layout#raptor-description) | [service_manager](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/service_manager.rb) | Used to manage connection services such as HTTP Server |
| [Raptor](https://github.com/rapid7/raptor/wiki/Rex-code-layout#raptor-description) | [text](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/text.rb) | Text Generation and manipulation routines. Core to almsot every aspect of Metasploit. |
| [Exploit Helper](https://github.com/rapid7/raptor/wiki/Rex-code-layout#exploit-helper) | [arch](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/arch/) | Important Architecture information such as registers, opcodes, and stack manipulation routines. |
| [Exploit Helper](https://github.com/rapid7/raptor/wiki/Rex-code-layout#exploit-helper) | [encoder](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/encoder/) | Encoder classes used by the encoder modules. (XDR moves to raptor though) |
| [Exploit Helper](https://github.com/rapid7/raptor/wiki/Rex-code-layout#exploit-helper) | [encoding](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/encoding/) | Serve as base classes to some of the things in Encoder. Needs to be merged together with Encoder |
| [Exploit Helper](https://github.com/rapid7/raptor/wiki/Rex-code-layout#exploit-helper) | [exploitation](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/exploitation/) | Grab Bag of Exploitation helpers such as ropdb, opcodedb, egghunter, seh routines etc |
| [Exploit Helper](https://github.com/rapid7/raptor/wiki/Rex-code-layout#exploit-helper) | [nop](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/nop/) | Library for generating multi-byte NOP routines |
| [Exploit Helper](https://github.com/rapid7/raptor/wiki/Rex-code-layout#exploit-helper) | [payloads](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/payloads/) | Contains Kernel mode wrapper for Windows payloads |
| [Exploit Helper](https://github.com/rapid7/raptor/wiki/Rex-code-layout#exploit-helper) | [poly](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/poly/) | Plymorphic code generation routines for polymorphic encoder modules |
| [Exploit Helper](https://github.com/rapid7/raptor/wiki/Rex-code-layout#exploit-helper) | [ropbuilder](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/ropbuilder/) | Library for building ROP chains |
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [assembly](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/assembly/) | NASM bindings for use with msfpescan and msfbinscan |
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [elfparsey](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/elfparsey/) | Parse and Maniuplate ELF executables |
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [elfscan](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/elfscan/) | Scanner for ELF executables |
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [imagesource](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/image_source/) | Interfaces for reading executables from File or memory |
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [marchparsey](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/machparsey/) | Library for parsing and manipulating Mach-O executables |
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [machscan](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/machscan/) | Scanner for Mach-O executables |
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [ole](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/ole/) | OLE Format creation, parsing and manipulations |
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [peparsey](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/peparsey) | Parsing and Maniuplation library for PE format executables|
| [Binary Manipulation](https://github.com/rapid7/raptor/wiki/Rex-code-layout#binary-manipulation) | [pescan](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/pescan) | Scanner for PE format executables |
| [Meterpreter Client](https://github.com/rapid7/raptor/wiki/Rex-code-layout#meterpreter-client) | [post](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/post/) | Meterepreter client-side API for talking to the Meterpreter agent |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [logging](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/logging/) | Classes for Metasploit logging |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [parser](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/parser) | Import parser classes for various import formats |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [platforms](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/platforms/) | Windows Registry Constants. Stick it with all the other registry mixins |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [sync](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/sync/) | Syncrhonization, thread locks etc. |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [ui](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/ui/) | UI code for the msfconsole interface etc.|
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [compat](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/compat.rb) | Routines for checking the local paltform and handling compatability issues |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [constants](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/constants.rb) | A big collection of constants used by framework, probably needs to be split up |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [exceptions](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/exceptions.rb) | A big collection of exceptions, probably needs split up |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [job_container](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/job_container.rb) | Job container for framework job management |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [thread_factory](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/thread_factory.rb) | Thread factory for Framework thread management |
| [Metasploit Core](https://github.com/rapid7/raptor/wiki/Rex-code-layout#metasploit-core) | [transformer](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/transformer.rb) | Some MetaProgramming magic rainbow unicorns. Used only in core, so move it there |
| [/dev/null](https://github.com/rapid7/raptor/wiki/Rex-code-layout#devnull) | [encoders](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/encoders/) | Deprecated Encoders. Unused.|
| [/dev/null](https://github.com/rapid7/raptor/wiki/Rex-code-layout#devnull) | [script](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex//script/) | library for dealing with meterpreter scripts, which are no longer supported. |
| [/dev/null](https://github.com/rapid7/raptor/wiki/Rex-code-layout#devnull) | [struct2](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/struct2/) | library for creating c-style binary structs. Replace with bitstruct |
| [?](https://github.com/rapid7/raptor/wiki/Rex-code-layout#wtf) | [registry](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/registry/) |  Offline local registry parsing library. Not sure where this belongs |
| [?](https://github.com/rapid7/raptor/wiki/Rex-code-layout#wtf) | [zip](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/zip/) | Library for parsing, creating, and manipulating Zip files |
| [?](https://github.com/rapid7/raptor/wiki/Rex-code-layout#wtf) | [file](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/file.rb) | Classes for dealing with extended fileutil options. Not sure where this belongs |
| [?](https://github.com/rapid7/raptor/wiki/Rex-code-layout#wtf) | [mac_oui](https://github.com/rapid7/metasploit-framework/tree/master/lib/rex/mac_oui.rb) | MAC address vendor lookup class |
