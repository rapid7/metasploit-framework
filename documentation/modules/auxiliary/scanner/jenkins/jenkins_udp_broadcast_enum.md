Jenkins is an open source tool that provides continuous integration services for software
development. This module will attempt to find Jenkins servers by performing a UDP
broadcast.

To use this module, you should be on the same network as the Jenkins server(s).


## Verification Steps

To test this module, you must make sure there is at least one Jenkins server on the same network.
To download Jenkins, please follow this link:

[https://jenkins.io/](https://jenkins.io/)


## Options

Unlike most Metasploit modules, jenkins_udp_broadcast_enum does not have any datastore options
to configure. So all you have to do is load it, and run, like this:

```
msf auxiliary(jenkins_udp_broadcast_enum) > run

[*] Sending Jenkins UDP Broadcast Probe ...
[*] 192.168.1.96 - Found Jenkins Server 1.638 Version
[*] Auxiliary module execution completed
```
Once you have found the Jenkins server, you should be able to browse to the web server.
And by default, that port is 8080.