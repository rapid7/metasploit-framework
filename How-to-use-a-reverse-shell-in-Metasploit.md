There are two popular types of shells: bind and reverse. A bind shell opens up a new service on the target machine, and requires the attacker to connect to it. A reverse shell (also known as a connect-back) is the exact opposite: it requires the attacker to set up a listener first on his box, the target machine acts as a client connecting to that listener, and then finally the attacker receives the shell.

The basic usage of payloads is already quite well documented in the [Users Guide](https://github.com/rapid7/metasploit-framework/blob/master/documentation/users_guide_4.3.pdf) in Metasploit's documentation folder. However, learning how to use a reverse shell still remains the most common question in the Metasploit community. Plus, 9 times out of 10 you'd probably be using a reverse shell to get a session, so in this wiki documentation we will explain more about this.

## List of Metasploit reverse shells

## When to use a reverse shell

If you find yourself in one of the following scenarios (but not limited to), then you should consider using a reverse shell:

* The target machine is behind a different private network.
* The target machine's firewall blocks incoming connection attempts to your bindshell.
* Your payload is unable to bind the port it wants due to whatever reason.
* You simply can't decide what to choose.

## When a reverse shell isn't needed

Generally speaking, if you can backdoor an existing service, you may not need a reverse shell. For example: if the target machine is already running a SSH server, then you can try adding a new user to it and use that.

If the target machine is running a web server that supports a server-side programming language, then you can leave a backdoor in that language. For example, many Apache servers support PHP, then you can use a PHP "web shell". IIS servers usually support ASP, or ASP.net.

Same thing for VNC, remote desktop, or other admin tools, etc.

## How to set up for a reverse shell

## Demonstration