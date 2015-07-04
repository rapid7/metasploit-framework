Dead shells. Nobody likes them. Yet, despite the advances made in the Metasploit stagers and Meterperter itself, we still see them regularly.

There are many reasons why shells refuse to connect, or die after they're established. The goal of this post is to help people understand _why_. Hopefully, by the end, the most common causes will be understood, and users can fix things themselves. If there are cases that are missed in this post, then please let us know and we'll add them.

Over time, this post should become a canonical resource for debugging sessions.

## Background Knowledge

Prior to diving into the possible breakages and their causes, it's important to have some background knowledge of stagers, and how Meterpreter works. Please be sure to read the following articles prior to reading the rest of this post:

* [[Meterpreter Stageless Mode]] - Covers the exploitation process, and how Meterpreter sessions are established. This is important because understanding how the different components interact, and what, allows for easier debugging later.
* [[Meterpreter Configuration]] - Covers how configuration works in Meterpreter. This is important because it highlights the separation of configuration in stagers and Meterpreter. This alone is the key to many breakages, especially in HTTP/S payloads.
* [[The ins and outs of HTTP and HTTPS communications in Meterpreter and Metasploit Stagers]] - Covers the detail of HTTP/S based communications in the stagers and in Meterpreter itself.

## Dead HTTP/S Shells

... todo ...
