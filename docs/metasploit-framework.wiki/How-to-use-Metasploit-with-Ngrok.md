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

1. Start a TCP tunnel using ngrok: `ngrok tcp localhost:4444`.
1. ngrok should start running and display a few settings, including a line that says "Forwarding". Note the host and IP
   address from this line, e.g. `4.tcp.ngrok.io:13779`
1. Start msfconsole and use the desired payload or exploit module.
  * Using `msfconsole` for both generating the payload and handling the connection is recommended over using `msfvenom`
    for two reasons.
    1. Using `msfvenom` starts up an instance of the framework to generate the payload, making it a slower process.
    2. Using `msfconsole` to configure both the payload and handler simultaneously ensures that the options are set for
       both, eliminating the possibility that they are out of sync.
1. Set the `LHOST` option to the address noted in step 2, `4.tcp.ngrok.io` in the example. This is where the payload is
   expecting to connect to.
1. Set the `LPORT` option to the port noted in step 2, `13779` in the example.
1. Set the `ReverseListenerBindAddress` option to `127.0.0.1`. This is where the connection will actually be accepted
   from ngrok.
1. Set the `ReverseListenerBindPort` option to `4444`.
1. Either run the exploit, or generate the payload with the `generate` command and start the handler with `to_handler`



[1]: https://ngrok.com/
