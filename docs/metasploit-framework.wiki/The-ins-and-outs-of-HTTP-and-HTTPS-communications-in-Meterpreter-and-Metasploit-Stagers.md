Recent changes to HTTP and HTTPS communications in both Meterpreter and its stagers have caused new behaviours that have left some users confused. The aim of this post is to cover the changes that have been made, the rationale behind those changes, and the issues that come with them. By the end of this post, readers should have a clear understanding of the issues related to HTTP/S communications, and be able to diagnose and fix any issues that they might be having.

## Windows HTTP APIs

The Windows API comes with two ways to talk via HTTP/S, they are [WinInet][] and [WinHTTP][]. The APIs are consumed in a similar fashion; many of the functions in each have the same interface, or are at least close enough to make a transition between the two rather trivial. However, there are some underlying differences that are important.

The [WinInet][] API was designed for use in desktop applications. It provides all the features required by applications to use HTTP/S while delegating much of the responsibility of handling implementation detail to the underlying API and OS. This API can result in some user interface elements appearing if not handled correctly.

[WinInet][] comes with some limitations, one of which is that it's close to impossible to do any kind of custom validation, parsing, or handling of SSL communications. One of the needs of Metasploit users is to be able to enable a [[Paranoid Mode|./meterpreter-paranoid-mode.md]] that forces Meterpreter to only talk with the appropriate endpoint. The goal is to prevent shells from being hijacked by unauthorised users. In order to do this, one of the things that was implemented was the verification of the SHA1 hash of the SSL certificate that Meterpreter reads from the server. If this hash doesn't match the one that Meterpreter is configured with, Meterpreter will shut down. [WinInet][] doesn't make this process possible without a _lot_ of custom work.

For applications such as this, [WinHTTP][] is the "preferred" option as deemed by Microsoft. This API is designed to work under a service, and provides a greater number of ways to interact with communications made over HTTP/S. With this API it was trivial to implement the SHA1 hash verification and force Meterpreter to shut down when a MITM is detected.

For a full comparison of the feature differences, please see [this feature matrix][winhttp_wininet] on MSDN.

## Meterpreter's Implementation

Meterpreter now makes use of [WinHTTP][] by default so that the new features are accommodated, but unfortuanetly this doesn't come for free. Behind the scenes, this API does not make any use of the current user's Internet Explorer configuration settings, where the [WinInet][] API does. This means that if the current user has a proxy configured, extra code needs to be added to make use of the current Internet Explorer settings in [WinHTTP][]. Meterpreter has been modified to do this, however there is still one limitation that is in place.

As indicated in a [blog post on MSDN][msdn_winhttp]:

> WinHTTP strictly requires HTTP/1.1 compliance for keeping the connection alive and HTTP Keep-Alives are not supported in HTTP/1.0 protocol. HTTP Keep-Alive feature was introduced in the HTTP/1.1 protocol as per RFC 2616. The server or the proxy which expects the keep-alive should also implement the protocol correctly. WinHTTP on Windows 7, Windows 2008 R2 are strict in terms of security wrto protocol compliance. The ideal solution is to change the server/proxy to use the right protocol and be RFC compliant.

What this means is that from Windows 7 and onwards, the underlying [WinHTTP][] implementation requires proper HTTP/1.1 support from any proxies that are used. If a proxy uses HTTP/1.0, such as Squid 2.7, and requires `Keep-Alive` support, such as NTLM authentication, then [WinHTTP][] will refuse to talk to it. Instead of downgrading, it will expect a purely RFC-compliant implementation, and instead will return a `407` error the client. This means that for Meterpreter to work, [WinHTTP][] can't be used.

In order to avoid this issue, [extra work][wininet_fallback] has been done to force Meterpreter to fall back to [WinInet][] when this happens. Given that [WinInet][] doesn't do certificate hash verification, this means that the user of Meterpreter loses the ability to use paranoid mode. It was decided that Meterpreter would not fallback to [WinInet][] if paranoid mode was enabled, as the intention of the user is clearly to avoid MITM.

To sum up, Meterpreter will use [WinHTTP][] where it can. If it can't, it'll fall back to [WinInet][] _unless_ paranoid mode is enabled.

## Metasploit HTTP and HTTPS Stagers

Metasploit users have long since known about the `reverse_http` and `reverse_https` stagers, and have made good use of them over time. What many _don't_ know is that these stagers use the [WinInet][] API, which means that they don't get SSL certificate validation (so no paranoid mode).

To provide support for paranoid mode directly inside the stager, ultimately preventing the download of Meterpreter _at all_ in the case of MITM, new stagers were required. `reverse_winhttp` and `reverse_winhttps` are implementations of stagers that make use of [WinHTTP][], and in the latter case, provides support for paranoid mode. They do, however come with the same implicit limitation as Meterpreter itself in that they may not be able to provide proxy support thanks to the strict RFC compliance described in the previous section. The big difference here is that the stager does _not_ have a fallback implementation like Meterpreter does, as this would make the stager way too big. Therefore, if an older proxy is in place that doesn't confirm to HTTP/1.1, the stager will fail.

## Combining Stagers with Meterpreter

It's important to note that the implementations of communications inside the stagers are completely separate to those inside Meterpreter. If you use `windows/meterpreter/reverse_https`, then the stager will use [WinInet][] and Meterpreter will use [WinHTTP][]. It isn't possible to "hand over" communications from the stager to Meterpreter in this case, and it wouldn't make sense anyway because HTTP/S is stateless. This is the most common set up because many people don't realise that the `reverse_winhttp/s` payloads exist!

Prior to the [WinInet fallback][wininet_fallback] work, those people hitting the HTTP/1.0 proxy issue would find themselves with the following scenario:

1. They would exploit a Windows 7 (or later) target in some way, whether it be via a browser exploit, or through a social engineering attack.
1. The payload that was executed was `meterpreter/reverse_https`, and so the initial connection would come via [WinInet][].
1. [WinInet][] would successfully use the current user's proxy configuration and the initial connection back to Metasploit would be successful.
1. The stager would download the second stage (`metsrv`), and reflectively load it so that Meterpreter could take over.
1. Meterpreter would attempt to connect again to Metasploit, this time using [WinHTTP][].
1. The proxy would return HTTP/1.0 responses, resulting in [WinHTTP][] refusing to function.
1. The Meterpreter session would be considered "dead" by Metasploit as a result of the lack of successful communications after staging.

Examples of these issues are [this](https://github.com/rapid7/metasploit-framework/issues/5462) and [this](https://github.com/rapid7/metasploit-framework/issues/5626). If you are seeing similar issues it's because your current Meterpreter binaries don't have the fallback option.

## Conclusion

HTTP/S communications in Windows is a hairy beast, and trying to cater for all cases proves to be quite tricky thanks to the limitations of some APIs, and the variable implementations of others. We're still working to iron out all of issues, and so please log an issue if you stumble on an edge case that hasn't yet been covered. Thank you for your patience!

[OJ][] / [@TheColonial][]


  [msdn_winhttp]: https://web.archive.org/web/20150701090733/http://blogs.msdn.com/b/httpcontext/archive/2012/02/21/changes-in-winhttp-on-windows-7-and-onwards-wrto-http-1-0.aspx
  [wininet_fallback]: https://github.com/rapid7/metasploit-payloads/pull/5
  [@TheColonial]: https://twitter.com/TheColonial
  [WinInet]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa383630%28v=vs.85%29.aspx
  [WinHTTP]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa382925%28v=vs.85%29.aspx
  [winhttp_wininet]: https://msdn.microsoft.com/en-us/library/windows/desktop/hh227298%28v=vs.85%29.aspx
  [OJ]: https://github.com/OJ
