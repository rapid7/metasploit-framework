Dead shells. Nobody likes them. Yet, despite the advances made in the Metasploit stagers and Meterperter itself, we still see them regularly.

There are many reasons why shells refuse to connect, or die after they're established. The goal of this post is to help people understand _why_. Hopefully, by the end, the most common causes will be understood, and users can fix things themselves. If there are cases that are missed in this post, then please let us know and we'll add them.

Over time, this post should become a canonical resource for debugging sessions.

## Background Knowledge

### Requisite Reading

Prior to diving into the possible breakages and their causes, it's important to have some background knowledge of stagers, and how Meterpreter works. Please be sure to read the following articles prior to reading the rest of this post:

* [[Meterpreter Stageless Mode]] - Covers the exploitation process, and how Meterpreter sessions are established. This is important because understanding how the different components interact, and what, allows for easier debugging later.
* [[Meterpreter Configuration]] - Covers how configuration works in Meterpreter. This is important because it highlights the separation of configuration in stagers and Meterpreter. This alone is the key to many breakages, especially in HTTP/S payloads.
* [[The ins and outs of HTTP and HTTPS communications in Meterpreter and Metasploit Stagers]] - Covers the detail of HTTP/S based communications in the stagers and in Meterpreter itself.

### Stagers, Stages, and Handlers

Each exploit and handler is made up of multiple things, and they're all independent:

* A **Stager**: This is the small bit of code that is first executed by the target. It contains it's own bundled implementation of a communications channel. It has the goal of establishing communication with Metasploit, downloading the **stage**, and invoking it. It has it's _own configuration_.
* A **Stage**: This is the second payload that is executed by the target. It is sent to the target via the communications channel that was opened by the **stage**. Once downloaded, it is invoked and from there it takes over. It has it's _own configuration_.
* A **Handler**: This is the code that runs on the attacker's machine. It is responsible for handling the attacker-side of the communications channel that is established by the **stager**. It is responsible for uploading the **stage**. It is responsible for handling communication between the attacker and the target once the stage has taken over from the stager.

In some cases there might be mulitple stages (as is the case with POSIX Meterpreter). This is called an **intermediate** stage. Usually these stages are slightly bigger than the stager and can do more work to help establish communications. In the context of this article, they aren't too important.

The most important thing to remember is that both the **stager** and the **stage** have their own configurations that are **independent**. _THE MOST COMMON_ cause of dead shells is the result of the **stage** not having the correct configuration (ie. it's different to that specified in the **stager**).

### LHOST and LPORT

Any user of Metasploit will tell you that they know what `LHOST` and `LPORT` mean, yet it's incredibly common to find out that their understanding isn't 100% correct. To prevent dead sessions that are related to misconfiguration of these values, we need to make sure we understand what they mean.

#### LHOST

`LHOST` is short for _Local Host_. This value represents the IP address or host name that **stagers** and **stages** should attempt to connect to. It is where the **handler** can be reached. This doesn't mean that this is where the handler actually _exists_.

`LHOST` is a value that meaning from the perspective of the target machine. This value is passed along as part of the configuration for **stagers** and **stages**, and tells the target machine where to go to reach the handler, and so this has to map to a value that _is reachable by the target_.

A **handler** obviously needs to listen on a host/IP for the incoming connection. In cases where the `LHOST` value (ie. the address that the target is able to reach) is the _same_ as that which the host can listen on, no extra work has to be done. The `LHOST` value is used by the handler.

However, if some kind of NAT or port forward is enabled, or if the handler is behind a firewall, etc, then setting `LHOST` isn't enough. In order to listen on the appropriate interface, another setting must be used called `ReverseListenerBindHost`. This value tells the **handler** to listen on a different interface/IP, but it doesn't change the fact that the `LHOST` value is given to the target when the **stage** is uploaded.

In short, `LHOST` must always remain the IP/host that is routable from the target, and if this value is not the same as what the listener needs to bind to, then change the `ReverseListenerBindHost` value. If you're attacking something across the Internet and you specific an internal IP in `LHOST`, you're doing it wrong.

## Dead HTTP/S Shells

