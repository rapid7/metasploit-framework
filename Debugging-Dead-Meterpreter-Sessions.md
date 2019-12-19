Dead shells. Nobody likes them. Yet, despite the advances made in the Metasploit stagers and Meterperter itself, we still see them regularly.

There are many reasons why shells refuse to connect, or die after they're established. The goal of this post is to help people understand _why_. Hopefully, by the end, the most common causes will be understood, and users can fix things themselves. If there are cases that are missed in this post, then please let us know and we'll add them.

Over time, this post should become a canonical resource for debugging sessions.

# Background Knowledge

## Requisite Reading

Prior to diving into the possible breakages and their causes, it's important to have some background knowledge of stagers, and how Meterpreter works. Please be sure to read the following articles prior to reading the rest of this post:

* [[Meterpreter Stageless Mode]] - Covers the exploitation process, and how Meterpreter sessions are established. This is important because understanding how the different components interact, and what, allows for easier debugging later.
* [[Meterpreter Configuration]] - Covers how configuration works in Meterpreter. This is important because it highlights the separation of configuration in stagers and Meterpreter. This alone is the key to many breakages, especially in HTTP/S payloads.
* [[The ins and outs of HTTP and HTTPS communications in Meterpreter and Metasploit Stagers]] - Covers the detail of HTTP/S based communications in the stagers and in Meterpreter itself.

# Stagers, Stages, and Handlers

Each exploit and handler is made up of multiple things, and they're all independent:

* **Stager**: This is the small bit of code that is first executed by the target. It contains it's own bundled implementation of a communications channel. It has the goal of establishing communication with Metasploit, downloading the **stage**, and invoking it. It has it's _own configuration_.
* **Stage**: This is the second payload that is executed by the target. It is sent to the target via the communications channel that was opened by the **stage**. Once downloaded, it is invoked and from there it takes over. It has it's _own configuration_.
* **Handler**: This is the code that runs on the attacker's machine. It is responsible for handling the attacker-side of the communications channel that is established by the **stager**. It is responsible for uploading the **stage**. It is responsible for handling communication between the attacker and the target once the stage has taken over from the stager.

In some cases there might be multiple stages (as is the case with POSIX Meterpreter). This is called an **intermediate** stage. Usually these stages are slightly bigger than the stager and can do more work to help establish communications. In the context of this article, they aren't too important.

The most important thing to remember is that both the **stager** and the **stage** have their own configurations that are **independent**. _THE MOST COMMON_ cause of dead shells is the result of the **stage** not having the correct configuration (ie. it's different to that specified in the **stager**).

# LHOST and LPORT

Any user of Metasploit will tell you that they know what `LHOST` and `LPORT` mean, yet it's incredibly common to find out that their understanding isn't 100% correct. To prevent dead sessions that are related to misconfiguration of these values, we need to make sure we understand what they mean.

## LHOST

`LHOST` is short for _Local Host_. This value represents the IP address or host name that **stagers** and **stages** should attempt to connect to. It is where the **handler** can be reached. This doesn't mean that this is where the handler actually _exists_.

`LHOST` is a value that meaning from the perspective of the target machine. This value is passed along as part of the configuration for **stagers** and **stages**, and tells the target machine where to go to reach the handler, and so this has to map to a value that _is reachable by the target_.

A **handler** obviously needs to listen on a host/IP for the incoming connection. In cases where the `LHOST` value (ie. the address that the target is able to reach) is the _same_ as that which the host can listen on, no extra work has to be done. The `LHOST` value is used by the handler.

However, if some kind of NAT or port forward is enabled, or if the handler is behind a firewall, etc, then setting `LHOST` isn't enough. In order to listen on the appropriate interface, another setting must be used called `ReverseListenerBindHost`. This value tells the **handler** to listen on a different interface/IP, but it doesn't change the fact that the `LHOST` value is given to the target when the **stage** is uploaded.

In short, `LHOST` must always remain the IP/host that is routable from the target, and if this value is not the same as what the listener needs to bind to, then change the `ReverseListenerBindHost` value. If you're attacking something across the Internet and you specify an internal IP in `LHOST`, you're doing it wrong.

## LPORT

The principles of `LHOST` / `ReverseListenerBindHost` can be applied to `LPORT` and `ReverseListenerBindPort` as well. If you have port forwarding in place, and your listener needs to bind to a different port, then you need to make use of the `ReverseListenerBindPort` setting.

The classic example of this case is where an attacker wants to make use of port `443`, but rightfully doesn't want to run Metasploit as `root` just so they can directly bind to ports lower than `1024`. Instead, the set up a port forward (on their router, or using `iptables`) so that `443` forwards to `8443`, with a goal of accepting connections on that port instead.

To accommodate this scenario, the `LHOST` value must **still contain `443`**, as this is the port that the target machine needs to establish communications on; `443` is the value that needs to go out with the **stager** and the **stage** configurations. Metasploit needs to bind locally to port `8443`, and so the **handler** is configured so that `ReverseListenerBindPort` has this value instead.

When the handler launches, it binds to `8443` and handles any connections it receives. When a stage is generated, it uses `443` from `LHOST` value to populate the configuration.

If the attacker makes the mistake of either setting `LPORT` to `8443`, or leaving `LPORT` as `443` and not using `ReverseListenerBindPort`, then the result is either a dead shell after the first stage, or no connect back at all.

# Dead Shells - What to check for?

## Quick things to check

* Make sure that `LHOST` is set to a routable address from the target, and not a local listen address.
* Make sure that `LPORT` is set to the port number that the target needs to connect to.
* Make sure that `ReverseListenerBindPort` is set if port forwarding is enabled and the traffic is being routed to a different port.
* Make sure that your listener's configuration matches that of the target from an architecture perspective. If you mix x64 listeners with x86 payloads (and vice versa), things will go bad.

## Not so quick things to check

* If the target is running AntiVirus there's a chance that the **stage** (ie. `metsrv`) is being caught while being uploaded. `reverse_tcp` and `reverse_http` **stagers** download `metsrv` _without_ any encryption, and so the content of the DLL is visible to anything watching on the wire. `reverse_https` can still get caught in cases where AV is doing MITM content inspection. In this case, consider encoding your payloads, or if possible using _stageless_ meterpreter instead. 

